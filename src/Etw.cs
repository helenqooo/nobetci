using System;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Nobetci
{
    public class ProcEvent { public int Pid; public int ParentPid; public string Image; public string CommandLine; public DateTime Time = DateTime.Now; }
    public class RegEvent { public int Pid; public string Key; public string Value; }
    public class FileEvent { public int Pid; public string Path; public string Op; }
    public class NetEvent { public int Pid; public string Addr; public int Port; }
    /// <summary>Kind: hook | rawinput | asynckey | clipread | clipwrite. Arg: hook type; OwnerPid: whose clipboard data was read.</summary>
    public class SpyEvent { public int Pid; public string Kind; public int Arg; public int OwnerPid; public string Lib; public bool HasModule; }

    /// <summary>Real-time kernel events (ETW): who started what, who wrote which registry value or file, who connected where.</summary>
    public sealed class EtwMonitor : IDisposable
    {
        public event Action<ProcEvent> ProcessStarted;
        public event Action<RegEvent> RegistryWritten;
        public event Action<FileEvent> FileChanged;
        public event Action<NetEvent> Connected;
        public event Action<SpyEvent> Spied;

        TraceEventSession session;
        Thread thread;
        public string Error;
        public System.Collections.Generic.List<string> DebugRaw;   // tests only: first raw registry events

        const string SessionName = "NobetciKernel";

        public bool Start()
        {
            try
            {
                TraceEventSession old = TraceEventSession.GetActiveSession(KernelTraceEventParser.KernelSessionName);
                if (old != null) old.Stop();
                session = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
                session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.FileIOInit |
                    KernelTraceEventParser.Keywords.FileIO |
                    KernelTraceEventParser.Keywords.NetworkTCPIP);

                KernelTraceEventParser k = session.Source.Kernel;
                // the first .exe mapped into a new process is the program itself, with its full path
                k.ImageLoad += d => { string f = d.FileName; if (d.ProcessID > 4 && f != null && f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) Procs.Loaded(d.ProcessID, f); };
                k.ProcessStart += d =>
                {
                    Procs.Started(d.ProcessID);
                    Action<ProcEvent> h = ProcessStarted;
                    if (h == null) return;
                    ProcEvent e = new ProcEvent();
                    e.Pid = d.ProcessID; e.ParentPid = d.ParentID; e.Image = d.ImageFileName; e.CommandLine = d.CommandLine;
                    h(e);
                };
                k.FileIOWrite += d => RaiseFile(d.ProcessID, d.FileName, "write");
                // 0x1000 = FILE_DELETE_ON_CLOSE: how cmd's "del" and many programs delete, with no separate delete event
                k.FileIOCreate += d => RaiseFile(d.ProcessID, d.FileName, ((int)d.CreateOptions & 0x1000) != 0 ? "delete" : "create");
                k.FileIORename += d => RaiseFile(d.ProcessID, d.FileName, "rename");
                k.FileIODelete += d => RaiseFile(d.ProcessID, d.FileName, "delete");
                k.TcpIpConnect += d =>
                {
                    Action<NetEvent> h = Connected;
                    if (h == null) return;
                    NetEvent e = new NetEvent();
                    e.Pid = d.ProcessID; e.Addr = d.daddr != null ? d.daddr.ToString() : ""; e.Port = d.dport;
                    h(e);
                };

                thread = new Thread(() =>
                {
                    try { session.Source.Process(); }
                    catch (Exception ex) { Error = ex.Message; }
                });
                thread.IsBackground = true;
                thread.Name = "etw";
                thread.Start();
                StartRegistrySession();
                StartWin32kSession();
                return true;
            }
            catch (Exception ex)
            {
                Error = ex.Message;
                return false;
            }
        }


        TraceEventSession regSession;
        Thread regThread;
        static readonly Guid RegistryProvider = new Guid("70EB4F03-C1DE-4F73-A051-33D13D5413BD");   // Microsoft-Windows-Kernel-Registry

        /// <summary>Registry writes only (SetValueKey / DeleteValueKey): the manifest provider carries the full key path.</summary>
        void StartRegistrySession()
        {
            try
            {
                TraceEventSession old = TraceEventSession.GetActiveSession("NobetciRegistry");
                if (old != null) old.Stop();
                regSession = new TraceEventSession("NobetciRegistry");
                regSession.EnableProvider(RegistryProvider, TraceEventLevel.Informational, 0x300UL);
                RegisteredTraceEventParser reg = new RegisteredTraceEventParser(regSession.Source);
                reg.All += d =>
                {
                    Action<RegEvent> h = RegistryWritten;
                    if (h == null) return;
                    System.Collections.Generic.List<string> dbg = DebugRaw;
                    if (dbg != null) lock (dbg) { if (dbg.Count < 6) { string pv = ""; try { for (int i = 0; i < d.PayloadNames.Length && i < 14; i++) pv += d.PayloadNames[i] + "=" + d.PayloadValue(i) + "; "; } catch { } dbg.Add(d.EventName + " pid=" + d.ProcessID + " " + pv); } }
                    string key = null, val = null;
                    try { key = d.PayloadByName("KeyName") as string; val = d.PayloadByName("ValueName") as string; } catch { }
                    if (string.IsNullOrEmpty(val)) return;   // the key path is usually empty in this provider; the value name and the writer are what we need
                    RegEvent e = new RegEvent();
                    e.Pid = d.ProcessID; e.Key = key; e.Value = val ?? "";
                    h(e);
                };
                regThread = new Thread(() => { try { regSession.Source.Process(); } catch (Exception ex) { Error = (Error ?? "") + " registry: " + ex.Message; } });
                regThread.IsBackground = true; regThread.Name = "etw-reg";
                regThread.Start();
            }
            catch (Exception ex) { Error = (Error ?? "") + " registry: " + ex.Message; }
        }

        TraceEventSession w32Session;
        Thread w32Thread;
        public bool SpyOk;
        static readonly Guid Win32kProvider = new Guid("8C416C79-D49B-4F01-A467-E56D3AA8234C");   // Microsoft-Windows-Win32k

        static int Num(TraceEvent d, string name)
        {
            try { object o = d.PayloadByName(name); return o == null ? 0 : Convert.ToInt32(o); } catch { return 0; }
        }

        /// <summary>
        /// Window-manager audit events: global keyboard hooks, raw keyboard input, key-state polling and clipboard access.
        /// This is the only driverless way to see a keylogger arm itself.
        /// </summary>
        void StartWin32kSession()
        {
            try
            {
                TraceEventSession old = TraceEventSession.GetActiveSession("NobetciWin32k");
                if (old != null) old.Stop();
                w32Session = new TraceEventSession("NobetciWin32k");
                // AuditApiCalls | ReadClipboard | WriteClipboard
                w32Session.EnableProvider(Win32kProvider, TraceEventLevel.Informational, 0x400UL | 0x80000000000UL | 0x40000000000UL);
                RegisteredTraceEventParser p = new RegisteredTraceEventParser(w32Session.Source);
                p.All += d =>
                {
                    Action<SpyEvent> h = Spied;
                    if (h == null) return;
                    SpyEvent e = null;
                    switch ((int)d.ID)
                    {
                        case 1002:   // SetWindowsHookEx
                            e = new SpyEvent { Pid = d.ProcessID, Kind = "hook", Arg = Num(d, "FilterType") };
                            try { e.Lib = d.PayloadByName("pstrLib") as string; } catch { }
                            try { object hm = d.PayloadByName("hmod"); e.HasModule = hm != null && Convert.ToUInt64(hm) != 0; } catch { }
                            break;
                        case 1001:   // RegisterRawInputDevices: usage page 1 / usage 6 = keyboard, 0x100 = RIDEV_INPUTSINK (receive while in the background)
                            if (Num(d, "UsagePage") == 1 && Num(d, "Usage") == 6 && (Num(d, "Flags") & 0x100) != 0 && Num(d, "ReturnValue") != 0)
                                e = new SpyEvent { Pid = d.ProcessID > 0 ? d.ProcessID : Num(d, "ProcessId"), Kind = "rawinput" };
                            break;
                        case 1003:   // GetAsyncKeyState polled from the background
                            e = new SpyEvent { Pid = d.ProcessID, Kind = "asynckey" };
                            break;
                        case 463:    // clipboard read
                            e = new SpyEvent { Pid = Num(d, "CallerPid"), Kind = "clipread", OwnerPid = Num(d, "OwnerPid") };
                            if (e.Pid <= 0) e.Pid = d.ProcessID;
                            break;
                        case 459:
                        case 460:    // clipboard write
                            e = new SpyEvent { Pid = d.ProcessID, Kind = "clipwrite" };
                            break;
                    }
                    if (e != null && e.Pid > 4) h(e);
                };
                w32Thread = new Thread(() => { try { w32Session.Source.Process(); } catch (Exception ex) { Error = (Error ?? "") + " win32k: " + ex.Message; } });
                w32Thread.IsBackground = true; w32Thread.Name = "etw-w32k";
                w32Thread.Start();
                SpyOk = true;
            }
            catch (Exception ex) { Error = (Error ?? "") + " win32k: " + ex.Message; }
        }

        void RaiseFile(int pid, string path, string op)
        {
            Action<FileEvent> h = FileChanged;
            if (h == null || string.IsNullOrEmpty(path)) return;
            FileEvent e = new FileEvent();
            e.Pid = pid; e.Path = path; e.Op = op;
            h(e);
        }

        public void Dispose()
        {
            try { if (session != null) session.Dispose(); } catch { }
            try { if (regSession != null) regSession.Dispose(); } catch { }
            try { if (w32Session != null) w32Session.Dispose(); } catch { }
        }
    }
}
