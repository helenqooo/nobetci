using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Nobetci
{
    /// <summary>Who we believe without looking further: admin-only locations, valid signatures, and what the user allowed.</summary>
    internal static class Trust
    {
        // signed Microsoft interpreters: whatever they do is the script's doing, so their signature proves nothing
        public static readonly HashSet<string> ScriptHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
              "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe" };

        class Entry { public bool Ok; public DateTime At; }
        static readonly Dictionary<string, Entry> cache = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);

        public static bool IsScriptHost(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) return false;
                // a copy of powershell.exe under another name is still powershell
                return ScriptHosts.Contains(Path.GetFileName(path)) || ScriptHosts.Contains(Procs.OriginalName(path));
            }
            catch { return false; }
        }

        public static bool IsTrusted(string path)
        {
            if (string.IsNullOrEmpty(path) || IsScriptHost(path)) return false;
            lock (cache)
            {
                Entry e;
                if (cache.TryGetValue(path, out e) && (DateTime.UtcNow - e.At).TotalSeconds < 120) return e.Ok;
            }
            bool ok = Rules.IsSystemLocation(path) || Sig.Check(path).Signed || Store.IsAllowed(Procs.Sha256(path));
            lock (cache)
            {
                if (cache.Count > 2000) cache.Clear();
                cache[path] = new Entry { Ok = ok, At = DateTime.UtcNow };
            }
            return ok;
        }

        public static void Forget(string path) { if (path != null) lock (cache) cache.Remove(path); }
    }

    /// <summary>
    /// Spyware behaviour: programs that listen to the keyboard (global hooks, raw input, key-state polling)
    /// or keep reading — or rewriting — the clipboard.
    /// </summary>
    public sealed class SpyGuard : IDisposable
    {
        readonly BlockingCollection<SpyEvent> work = new BlockingCollection<SpyEvent>(2000);
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        readonly Dictionary<int, List<DateTime>> clipReads = new Dictionary<int, List<DateTime>>();
        readonly int self = Process.GetCurrentProcess().Id;
        Thread worker;

        public bool Dry;
        /// <summary>Self-test only: lets the test process play the spy.</summary>
        public bool IncludeSelf;

        public void Start()
        {
            worker = new Thread(() =>
            {
                foreach (SpyEvent e in work.GetConsumingEnumerable())
                {
                    try { Handle(e); } catch { }
                }
            });
            worker.IsBackground = true;
            worker.Name = "spy";
            worker.Start();
        }

        public void OnSpy(SpyEvent e) { if (e.Pid != self || IncludeSelf) work.TryAdd(e); }

        bool Seen(string key, int seconds)
        {
            lock (recent)
            {
                DateTime t;
                DateTime now = DateTime.UtcNow;
                if (recent.TryGetValue(key, out t) && (now - t).TotalSeconds < seconds) return true;
                if (recent.Count > 2000) recent.Clear();
                recent[key] = now;
                return false;
            }
        }

        void Handle(SpyEvent e)
        {
            Sev sev; string what, why;
            switch (e.Kind)
            {
                case "hook":
                    // 13 = WH_KEYBOARD_LL (always system-wide), 2 = WH_KEYBOARD and 0 = WH_JOURNALRECORD (system-wide when a module is given)
                    if (e.Arg == 13) { what = "klavyeyi dinliyor"; why = "Sistem genelinde klavye kancası kurdu (WH_KEYBOARD_LL): basılan her tuşu görebilir."; }
                    else if ((e.Arg == 2 || e.Arg == 0) && e.HasModule) { what = "klavyeyi dinliyor"; why = "Diğer programlara klavye kancası yerleştirdi (" + (e.Arg == 2 ? "WH_KEYBOARD" : "WH_JOURNALRECORD") + ")."; }
                    else return;
                    sev = Sev.Danger;
                    break;
                case "rawinput":
                    sev = Sev.Danger; what = "klavyeyi dinliyor";
                    why = "Arka plandayken ham klavye girdisine abone oldu (RIDEV_INPUTSINK): başka pencerelere yazılan tuşları alır.";
                    break;
                case "asynckey":
                    sev = Sev.Warn; what = "arka planda tuşları yokluyor";
                    why = "Penceresi önde değilken tuş durumunu sorguluyor (GetAsyncKeyState): basit tuş kaydedicilerin yöntemi.";
                    break;
                case "clipread":
                    if (e.OwnerPid == e.Pid || e.OwnerPid == 0) return;
                    lock (clipReads)
                    {
                        List<DateTime> l;
                        if (!clipReads.TryGetValue(e.Pid, out l)) { if (clipReads.Count > 500) clipReads.Clear(); clipReads[e.Pid] = l = new List<DateTime>(); }
                        DateTime now = DateTime.UtcNow;
                        l.Add(now);
                        l.RemoveAll(t => (now - t).TotalSeconds > 60);
                        if (l.Count < 4) return;
                    }
                    sev = Sev.Warn; what = "panoyu okuyor";
                    why = "Başka programların kopyaladığı içeriği tekrar tekrar okuyor (parola, kripto adresi gibi şeyler panodan geçer).";
                    break;
                case "clipwrite":
                    // a clipper reads what you copied and swaps it straight away
                    lock (clipReads)
                    {
                        List<DateTime> l;
                        if (!clipReads.TryGetValue(e.Pid, out l) || l.Count == 0 || (DateTime.UtcNow - l[l.Count - 1]).TotalSeconds > 2) return;
                    }
                    sev = Sev.Danger; what = "panoyu değiştiriyor";
                    why = "Başkasının kopyaladığı içeriği okuyup hemen ardından panoya kendi verisini yazdı (kripto adresi değiştiren yazılımların davranışı).";
                    break;
                default: return;
            }

            string path = Procs.ImagePath(e.Pid);
            if (path == null) return;                       // already gone, and its hooks went with it
            if (Trust.IsTrusted(path)) return;
            string name = Path.GetFileName(path);
            if (Seen(e.Kind + ":" + path, e.Kind == "hook" || e.Kind == "rawinput" ? 60 : 300)) return;

            SigInfo sig = Sig.Check(path);
            string detail = why + Environment.NewLine +
                "Program: " + path + " (PID " + e.Pid + ")" + Environment.NewLine +
                (sig.Signed ? "Yayıncı: " + sig.Publisher : Trust.IsScriptHost(path) ? "Bir betik çalıştırıcısı: asıl işi yapan, çalıştırdığı betik." : "İmza: yok") +
                (string.IsNullOrEmpty(e.Lib) ? "" : Environment.NewLine + "Kanca modülü: " + e.Lib);

            Alert a = new Alert(sev, "spy", name + " " + what, detail);
            int pid = e.Pid;
            bool ask = Settings.Mode == "ask" && !Dry && !Settings.Paused && sev == Sev.Danger;
            if (ask && Procs.Suspend(pid))
            {
                a.Pending = true;
                a.Title = name + " durduruldu: " + what;
                a.Actions.Add(new AlertAction("İzin ver", () => { Procs.Resume(pid); Store.Allow(Procs.Sha256(path), path); Trust.Forget(path); a.Pending = false; a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Engelle", () => { Procs.Kill(pid); a.Pending = false; a.Resolved = true; }));
            }
            else
            {
                if (!Dry) a.Actions.Add(new AlertAction("Sonlandır", () => { Procs.Kill(pid); a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Güvenilir yap", () => { Store.Allow(Procs.Sha256(path), path); Trust.Forget(path); a.Resolved = true; }));
            }
            Hub.Raise(a);
        }

        public void Dispose() { try { work.CompleteAdding(); } catch { } }
    }
}
