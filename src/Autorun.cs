using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace Nobetci
{
    public class AutorunEntry
    {
        public string Id;      // stable identity, for example "run|HKU\S-1-5-21...\...\Run|OneDrive"
        public string Kind;    // run | service | task | startup | ifeo | winlogon | appinit | wmi
        public string Where;
        public string Name;
        public string Value;
    }

    /// <summary>Everything that can start by itself, snapshotted and compared. Catches what the live events miss.</summary>
    public sealed class AutorunWatch : IDisposable
    {
        static readonly string[] RunKeys =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        };

        Dictionary<string, AutorunEntry> known;
        Dictionary<string, string> baseline;      // id -> value, persisted
        Timer timer;
        int busy;
        public bool Dry;
        public int IntervalMs = 3000;
        public bool QuietFirstRun = true;

        // ---------------------------------------------------------------- snapshot

        public static Dictionary<string, AutorunEntry> Snapshot()
        {
            Dictionary<string, AutorunEntry> d = new Dictionary<string, AutorunEntry>(StringComparer.OrdinalIgnoreCase);
            try { Runs(d); } catch { }
            try { Services(d); } catch { }
            try { Tasks(d); } catch { }
            try { Startup(d); } catch { }
            try { Ifeo(d); } catch { }
            try { Winlogon(d); } catch { }
            try { Wmi(d); } catch { }
            return d;
        }

        static void Add(Dictionary<string, AutorunEntry> d, string kind, string where, string name, string value)
        {
            AutorunEntry e = new AutorunEntry();
            e.Kind = kind; e.Where = where; e.Name = name; e.Value = value ?? "";
            e.Id = kind + "|" + where + "|" + name;
            d[e.Id] = e;
        }

        static void ReadValues(Dictionary<string, AutorunEntry> d, RegistryKey root, string rootName, string sub, string kind)
        {
            using (RegistryKey k = root.OpenSubKey(sub))
            {
                if (k == null) return;
                foreach (string n in k.GetValueNames())
                {
                    object v = k.GetValue(n);
                    Add(d, kind, rootName + "\\" + sub, n, v == null ? "" : v.ToString());
                }
            }
        }

        static void Runs(Dictionary<string, AutorunEntry> d)
        {
            foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using (RegistryKey lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    foreach (string s in RunKeys) ReadValues(d, lm, "HKLM" + (view == RegistryView.Registry32 ? "32" : ""), s, "run");
            }
            using (RegistryKey users = Registry.Users)
            {
                foreach (string sid in users.GetSubKeyNames())
                {
                    if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) || sid == ".DEFAULT") continue;
                    using (RegistryKey u = users.OpenSubKey(sid))
                    {
                        if (u == null) continue;
                        foreach (string s in RunKeys) ReadValues(d, u, "HKU\\" + sid, s, "run");
                    }
                }
            }
        }

        static void Services(Dictionary<string, AutorunEntry> d)
        {
            using (RegistryKey svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (svc == null) return;
                foreach (string n in svc.GetSubKeyNames())
                {
                    using (RegistryKey k = svc.OpenSubKey(n))
                    {
                        if (k == null) continue;
                        object img = k.GetValue("ImagePath");
                        if (img == null) continue;
                        object type = k.GetValue("Type"); object start = k.GetValue("Start");
                        Add(d, "service", "Services", n, (type ?? "") + "|" + (start ?? "") + "|" + img);
                    }
                }
            }
        }

        static string TasksDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks"); } }

        static void Tasks(Dictionary<string, AutorunEntry> d)
        {
            string dir = TasksDir;
            if (!Directory.Exists(dir)) return;
            foreach (string f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                try
                {
                    FileInfo fi = new FileInfo(f);
                    string rel = f.Substring(dir.Length).TrimStart('\\');
                    Add(d, "task", "Tasks", rel, fi.LastWriteTimeUtc.Ticks + "|" + fi.Length);
                }
                catch { }
            }
        }

        static void Startup(Dictionary<string, AutorunEntry> d)
        {
            List<string> dirs = new List<string>();
            dirs.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"));
            string users = Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)), "Users");
            try
            {
                foreach (string u in Directory.GetDirectories(users))
                    dirs.Add(Path.Combine(u, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
            }
            catch { }
            foreach (string dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (string f in Directory.GetFiles(dir))
                {
                    if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    try { Add(d, "startup", dir, Path.GetFileName(f), new FileInfo(f).Length.ToString()); } catch { }
                }
            }
        }

        static void Ifeo(Dictionary<string, AutorunEntry> d)
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
            {
                if (k == null) return;
                foreach (string n in k.GetSubKeyNames())
                {
                    using (RegistryKey s = k.OpenSubKey(n))
                    {
                        object dbg = s == null ? null : s.GetValue("Debugger");
                        if (dbg != null) Add(d, "ifeo", "IFEO", n, dbg.ToString());
                    }
                }
            }
        }

        static void Winlogon(Dictionary<string, AutorunEntry> d)
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
            {
                if (k != null)
                    foreach (string n in new[] { "Shell", "Userinit", "Taskman" })
                    {
                        object v = k.GetValue(n);
                        if (v != null) Add(d, "winlogon", "Winlogon", n, v.ToString());
                    }
            }
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"))
            {
                if (k == null) return;
                object a = k.GetValue("AppInit_DLLs");
                if (a != null && a.ToString().Trim() != "") Add(d, "appinit", "Windows", "AppInit_DLLs", a.ToString());
            }
        }

        static void Wmi(Dictionary<string, AutorunEntry> d)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __FilterToConsumerBinding"))
            using (ManagementObjectCollection c = s.Get())
            {
                foreach (ManagementBaseObject o in c)
                {
                    Add(d, "wmi", "subscription", Convert.ToString(o["Filter"]), Convert.ToString(o["Consumer"]));
                    o.Dispose();
                }
            }
        }

        // ---------------------------------------------------------------- baseline file

        static Dictionary<string, string> LoadBaseline()
        {
            string text = Store.ReadFile("autorun.base");
            if (text == null) return null;
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in text.Split('\n'))
            {
                string l = line.TrimEnd('\r');
                int i = l.IndexOf('\t');
                if (i <= 0) continue;
                d[Unesc(l.Substring(0, i))] = Unesc(l.Substring(i + 1));
            }
            return d;
        }

        static string Esc(string s) { return (s ?? "").Replace("\\", "\\\\").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n"); }
        static string Unesc(string s) { return Regex.Replace(s, @"\\([\\trn])", m => m.Groups[1].Value == "t" ? "\t" : m.Groups[1].Value == "r" ? "\r" : m.Groups[1].Value == "n" ? "\n" : "\\"); }

        void SaveBaseline()
        {
            StringBuilder sb = new StringBuilder();
            lock (baseline) { foreach (KeyValuePair<string, string> kv in baseline) sb.Append(Esc(kv.Key)).Append('\t').Append(Esc(kv.Value)).Append('\n'); }
            Store.WriteFile("autorun.base", sb.ToString());
        }

        // ---------------------------------------------------------------- run

        public void Start()
        {
            known = Snapshot();
            baseline = LoadBaseline();
            if (baseline == null)
            {
                baseline = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (AutorunEntry e in known.Values) baseline[e.Id] = e.Value;
                SaveBaseline();
                if (QuietFirstRun)
                    Hub.Raise(new Alert(Sev.Info, "autorun", "İlk ölçüm alındı", known.Count + " otomatik başlayan kayıt şu anki hâliyle güvenilir kabul edildi."));
            }
            else
            {
                // changes made while the guard was not running
                foreach (AutorunEntry e in known.Values)
                {
                    string old;
                    if (!baseline.TryGetValue(e.Id, out old)) Report(e, null);
                    else if (old != e.Value && e.Kind != "task") Report(e, old);
                }
            }
            timer = new Timer(_ => Tick(), null, IntervalMs, IntervalMs);
        }

        void Tick()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try
            {
                Dictionary<string, AutorunEntry> now = Snapshot();
                foreach (AutorunEntry e in now.Values)
                {
                    AutorunEntry prev;
                    if (!known.TryGetValue(e.Id, out prev)) Report(e, null);
                    else if (prev.Value != e.Value) Report(e, prev.Value);
                }
                known = now;
            }
            catch { }
            finally { Interlocked.Exchange(ref busy, 0); }
        }

        static readonly Dictionary<string, string> KindName = new Dictionary<string, string>
        {
            { "run", "Başlangıç kaydı" }, { "service", "Servis / sürücü" }, { "task", "Zamanlanmış görev" }, { "startup", "Başlangıç klasörü" },
            { "ifeo", "IFEO yönlendirmesi" }, { "winlogon", "Oturum açma kaydı" }, { "appinit", "AppInit DLL" }, { "wmi", "WMI kalıcılığı" }
        };

        // The kernel's "who wrote it" event can arrive a moment after the change is visible, so registry-based entries wait briefly.
        void Report(AutorunEntry e, string oldValue)
        {
            bool registry = e.Kind == "run" || e.Kind == "ifeo" || e.Kind == "winlogon" || e.Kind == "appinit";
            if (!registry || oldValue != null && false) { ReportNow(e, oldValue); return; }
            ThreadPool.QueueUserWorkItem(_ => { Thread.Sleep(1800); try { ReportNow(e, oldValue); } catch { } });
        }

        void ReportNow(AutorunEntry e, string oldValue)
        {
            string old;
            lock (baseline) { if (baseline.TryGetValue(e.Id, out old) && old == e.Value) return; }

            // services in the default drivers location and the usual updaters are too noisy to prompt about; log them quietly
            Sev sev = Sev.Warn;
            if (e.Kind == "ifeo" || e.Kind == "appinit" || e.Kind == "wmi" || e.Kind == "winlogon") sev = Sev.Danger;
            if (e.Kind == "service" && e.Value.ToLowerInvariant().Contains(".sys")) sev = Sev.Danger;
            bool byovd = e.Kind == "service" && Drivers.KnownName(e.Value);

            string value = e.Value;
            if (e.Kind == "task") value = TaskCommand(e.Name) ?? value;
            string title = (KindName.ContainsKey(e.Kind) ? KindName[e.Kind] : e.Kind) + (oldValue == null ? " eklendi: " : " değişti: ") + Short(e.Name, 60);
            string detail = "Konum: " + e.Where + Environment.NewLine + "İçerik: " + Short(value, 300) + (oldValue != null && e.Kind != "task" ? Environment.NewLine + "Eskisi: " + Short(oldValue, 200) : "");

            // who wrote it? (kernel registry events, matched by value name)
            string valueName = e.Kind == "run" ? e.Name : e.Kind == "ifeo" ? "Debugger" : e.Kind == "winlogon" ? e.Name : e.Kind == "appinit" ? "AppInit_DLLs" : null;
            int wpid = 0; string who = null;
            if (valueName != null && BehaviorGuard.Current != null) who = BehaviorGuard.Current.WhoWrote(valueName, out wpid);
            if (who != null) detail += Environment.NewLine + "Yazan program: " + who;
            if (byovd) detail += Environment.NewLine + "Bu, güvenlik yazılımlarını çekirdekten kapatmak için kötüye kullanılan bilinen zafiyetli sürücülerden biri (BYOVD).";

            Alert a = new Alert(sev, "autorun", title, detail);
            AutorunEntry copy = e;
            int killPid = wpid;
            if (!Dry && who != null && killPid > 4) a.Actions.Add(new AlertAction("Yazan programı sonlandır", () => { Procs.Kill(killPid); a.Resolved = true; }));
            if (!Dry && oldValue == null) a.Actions.Add(new AlertAction("Kaldır", () => { Remove(copy); a.Resolved = true; }));
            a.Actions.Add(new AlertAction("Güvenli, kabul et", () => { lock (baseline) baseline[copy.Id] = copy.Value; SaveBaseline(); a.Resolved = true; }));
            Hub.Raise(a);
        }

        static string Short(string s, int n) { s = (s ?? "").Replace("\r", " ").Replace("\n", " "); return s.Length <= n ? s : s.Substring(0, n) + "…"; }

        static string TaskCommand(string rel)
        {
            try
            {
                string xml = File.ReadAllText(Path.Combine(TasksDir, rel));
                Match c = Regex.Match(xml, @"<Command>(.*?)</Command>", RegexOptions.Singleline);
                Match a = Regex.Match(xml, @"<Arguments>(.*?)</Arguments>", RegexOptions.Singleline);
                if (!c.Success) return null;
                return c.Groups[1].Value + (a.Success ? " " + a.Groups[1].Value : "");
            }
            catch { return null; }
        }

        // ---------------------------------------------------------------- removal

        public static bool Remove(AutorunEntry e)
        {
            try
            {
                switch (e.Kind)
                {
                    case "run":
                    {
                        string w = e.Where;
                        RegistryKey root; string sub;
                        if (w.StartsWith("HKLM32\\")) { root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32); sub = w.Substring(7); }
                        else if (w.StartsWith("HKLM\\")) { root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); sub = w.Substring(5); }
                        else { root = Registry.Users; sub = w.Substring(4); }
                        using (RegistryKey k = root.OpenSubKey(sub, true)) { if (k != null) k.DeleteValue(e.Name, false); }
                        return true;
                    }
                    case "service":
                        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + e.Name, true))
                        { if (k != null) k.SetValue("Start", 4, RegistryValueKind.DWord); }
                        return true;
                    case "task":
                        Run("schtasks.exe", "/Change /TN \"" + e.Name.Replace("\\", "\\") + "\" /DISABLE");
                        return true;
                    case "startup":
                    {
                        string f = Path.Combine(e.Where, e.Name);
                        string q = Path.Combine(Store.Dir, "quarantine");
                        Directory.CreateDirectory(q);
                        File.Move(f, Path.Combine(q, DateTime.Now.ToString("yyyyMMddHHmmss") + "_" + e.Name));
                        return true;
                    }
                    case "ifeo":
                        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + e.Name, true))
                        { if (k != null) k.DeleteValue("Debugger", false); }
                        return true;
                    case "appinit":
                        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", true))
                        { if (k != null) k.SetValue("AppInit_DLLs", ""); }
                        return true;
                    case "wmi":
                        using (ManagementObjectSearcher s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __FilterToConsumerBinding"))
                        foreach (ManagementObject o in s.Get())
                            if (Convert.ToString(o["Filter"]) == e.Name) { o.Delete(); }
                        return true;
                }
            }
            catch { }
            return false;
        }

        static void Run(string exe, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.CreateNoWindow = true; psi.UseShellExecute = false;
            using (Process p = Process.Start(psi)) { p.WaitForExit(8000); }
        }

        public void Dispose() { if (timer != null) timer.Dispose(); }
    }
}
