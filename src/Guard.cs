using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace Nobetci
{
    /// <summary>
    /// Turns kernel events into alerts: suspicious command lines, unknown programs in user folders, odd parent/child pairs,
    /// and writes to persistence points and to hosts, with the culprit process named.
    /// </summary>
    public sealed class BehaviorGuard
    {
        readonly BlockingCollection<Action> work = new BlockingCollection<Action>(5000);
        readonly Dictionary<int, string> pathCache = new Dictionary<int, string>();
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        readonly int self = Process.GetCurrentProcess().Id;
        Thread worker;

        /// <summary>When true nothing is ever suspended or killed, alerts only (used on servers and in tests).</summary>
        public bool Dry;
        public string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

        static readonly HashSet<string> OfficeParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe" };
        static readonly HashSet<string> ScriptChildren = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe" };
        // signed Microsoft tools attackers use as their hands: being signed does not make their registry writes harmless
        static readonly HashSet<string> LolBins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "reg.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "sc.exe", "schtasks.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe" };
        static readonly HashSet<string> DefenderOwn = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "mpdlpservice.exe", "mssense.exe" };

        public void Start()
        {
            Current = this;
            worker = new Thread(() =>
            {
                foreach (Action a in work.GetConsumingEnumerable())
                {
                    try { a(); } catch { }
                }
            });
            worker.IsBackground = true;
            worker.Name = "guard";
            worker.Start();
        }

        public void OnProcess(ProcEvent e) { if (e.Pid != self) work.TryAdd(() => HandleProcess(e)); }
        public void OnRegistry(RegEvent e) { if (e.Pid != self) HandleRegistry(e); }
        public void OnFile(FileEvent e) { if (e.Pid != self) work.TryAdd(() => HandleFile(e)); }

        // ---------------------------------------------------------------- processes

        string PathOf(int pid, string fallback)
        {
            lock (pathCache)
            {
                string p;
                if (pathCache.TryGetValue(pid, out p)) return p;
            }
            string path = (fallback != null ? Procs.ImagePathWait(pid, 300) : Procs.ImagePath(pid)) ?? fallback;
            lock (pathCache)
            {
                if (pathCache.Count > 3000) pathCache.Clear();
                pathCache[pid] = path;
            }
            return path;
        }

        static string NameOf(string path) { try { return Path.GetFileName(path ?? ""); } catch { return path ?? ""; } }

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

        void HandleProcess(ProcEvent e)
        {
            string path = PathOf(e.Pid, e.Image);
            string name = NameOf(path ?? e.Image);
            string parentPath = PathOf(e.ParentPid, null);
            string parent = NameOf(parentPath);

            List<Finding> findings = Rules.CheckCommandLine(e.CommandLine);

            if (OfficeParents.Contains(parent) && ScriptChildren.Contains(name))
                findings.Add(new Finding(Sev.Danger, "office-child", parent + " bir komut yorumlayıcısı başlattı (belge makrosu olabilir)"));

            bool system = Rules.IsSystemLocation(path);
            SigInfo sig = null;
            bool unknownDropper = false;
            if (!system && !string.IsNullOrEmpty(path) && File.Exists(path))
            {
                sig = Sig.Check(path);
                if (!sig.Signed && Settings.Strict && Rules.IsUserWritable(path))
                    unknownDropper = true;
                // what the file itself is able to do (cached, so a program is read once)
                ScanResult scan = Scanner.ScanFile(path);
                if (scan.Verdict > 0)
                    findings.Add(new Finding(scan.Verdict == 2 ? Sev.Danger : Sev.Warn, "scan", "Dosya taraması (" + scan.Score + "/100): " + scan.Summary()));
            }

            string sha = null;
            if (unknownDropper)
            {
                sha = Procs.Sha256(path);
                if (Store.IsAllowed(sha)) unknownDropper = false;
            }
            if (findings.Count == 0 && !unknownDropper) return;

            Sev sev = Sev.Info;
            foreach (Finding f in findings) if (f.Severity > sev) sev = f.Severity;
            if (unknownDropper && sev < Sev.Warn) sev = Sev.Warn;

            if (Seen("p:" + name + ":" + (e.CommandLine ?? "").GetHashCode(), 20)) return;

            List<string> why = findings.Select(f => f.Text).ToList();
            if (unknownDropper) why.Add("İmzasız program, kullanıcı klasöründen başlatıldı");

            string detail = string.Join("; ", why) + Environment.NewLine +
                "Program: " + (path ?? e.Image) + "  (PID " + e.ParentPid + " → " + e.Pid + ", üst: " + (parent == "" ? "?" : parent) + ")" + Environment.NewLine +
                (sig != null && sig.Signed ? "Yayıncı: " + sig.Publisher + Environment.NewLine : "") +
                "Komut: " + Trunc(e.CommandLine, 400);

            Alert a = new Alert(sev, "process", name + " şüpheli davranıyor", detail);
            bool ask = Settings.Mode == "ask" && !Dry && !Settings.Paused && (sev == Sev.Danger || unknownDropper) && e.Pid != 4;
            int pid = e.Pid;
            if (ask && Procs.Suspend(pid))
            {
                a.Pending = true;
                a.Title = name + " durduruldu, karar bekliyor";
                a.Actions.Add(new AlertAction("İzin ver", () => { Procs.Resume(pid); if (sha != null) Store.Allow(sha, path); a.Pending = false; a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Engelle", () => { Procs.Kill(pid); a.Pending = false; a.Resolved = true; }));
            }
            else
            {
                a.Actions.Add(new AlertAction("Sonlandır", () => { Procs.Kill(pid); a.Resolved = true; }));
                if (unknownDropper)
                    a.Actions.Add(new AlertAction("Güvenilir yap", () => { Store.Allow(sha ?? Procs.Sha256(path), path); a.Resolved = true; }));
            }
            Hub.Raise(a);
        }

        static string Trunc(string s, int n) { s = s ?? ""; return s.Length <= n ? s : s.Substring(0, n) + "…"; }

        // ---------------------------------------------------------------- registry writes
        // The kernel reports who wrote which value name, not which key. The autorun / tamper snapshots know which key changed,
        // so they ask here "who wrote a value called X in the last minute?" to name the culprit.

        class RegWrite { public DateTime Time; public int Pid; public string Value; }
        readonly List<RegWrite> writes = new List<RegWrite>();
        public static BehaviorGuard Current;

        void HandleRegistry(RegEvent e)
        {
            if (string.IsNullOrEmpty(e.Value)) return;
            lock (writes)
            {
                writes.Add(new RegWrite { Time = DateTime.UtcNow, Pid = e.Pid, Value = e.Value });
                if (writes.Count > 4000) writes.RemoveRange(0, 1500);
            }
        }

        /// <summary>The program that most recently wrote a registry value with this name, e.g. "reg.exe (PID 1234)".</summary>
        public string WhoWrote(string valueName, out int pid)
        {
            pid = 0;
            if (string.IsNullOrEmpty(valueName)) return null;
            DateTime limit = DateTime.UtcNow.AddSeconds(-90);
            RegWrite hit = null;
            lock (writes)
            {
                for (int i = writes.Count - 1; i >= 0; i--)
                {
                    RegWrite w = writes[i];
                    if (w.Time < limit) break;
                    if (w.Pid != 4 && w.Pid != self && string.Equals(w.Value, valueName, StringComparison.OrdinalIgnoreCase)) { hit = w; break; }
                }
            }
            if (hit == null) return null;
            pid = hit.Pid;
            string path = PathOf(hit.Pid, null);
            return (string.IsNullOrEmpty(path) ? "bilinmeyen program" : path) + " (PID " + hit.Pid + ")";
        }

        // ---------------------------------------------------------------- file changes

        void HandleFile(FileEvent e)
        {
            string p = e.Path ?? "";
            string lp = p.ToLowerInvariant();
            bool hosts = lp.EndsWith(@"\drivers\etc\hosts") || lp.EndsWith(HostsPath.ToLowerInvariant());
            bool write = e.Op == "write" || e.Op == "rename" || e.Op == "delete";

            Sev sev = Sev.Info; string what = null;
            if (hosts && write) { sev = Sev.Danger; what = "hosts dosyasına yazdı"; }
            else if (e.Op == "create" && lp.Contains(@"\start menu\programs\startup\") && !lp.EndsWith("desktop.ini")) { sev = Sev.Warn; what = "Başlangıç klasörüne dosya bıraktı"; }
            else if (e.Op == "create" && lp.EndsWith(".sys") && (lp.Contains(@"\drivers\") || Rules.IsUserWritable(lp))) { sev = Sev.Warn; what = "Bir sürücü dosyası (.sys) bıraktı"; }
            if (what == null) return;

            string path = PathOf(e.Pid, null);
            string name = NameOf(path);
            if (name == "" || e.Pid == 4 || DefenderOwn.Contains(name)) return;
            if (name.Equals("TrustedInstaller.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) && sev == Sev.Warn) return;
            if (Seen("f:" + name + ":" + lp, 30)) return;

            Alert a = new Alert(sev, hosts ? "hosts" : "file", name + " " + what, "Program: " + path + " (PID " + e.Pid + ")" + Environment.NewLine + "Dosya: " + Trunc(p, 260));
            int pid = e.Pid;
            if (!Dry) a.Actions.Add(new AlertAction("Programı sonlandır", () => { Procs.Kill(pid); a.Resolved = true; }));
            Hub.Raise(a);
        }
    }
}
