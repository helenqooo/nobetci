using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Nobetci
{
    public enum Sev { Info = 0, Warn = 1, Danger = 2 }

    public class AlertAction
    {
        public string Label;
        public Action Run;
        public AlertAction(string label, Action run) { Label = label; Run = run; }
    }

    public class Alert
    {
        public DateTime Time = DateTime.Now;
        public Sev Severity;
        public string Kind;      // process | autorun | hosts | firewall | defender | service
        public string Title;
        public string Detail;
        public bool Pending;     // waiting for the user's decision (a suspended process, for instance)
        public bool Resolved;
        public List<AlertAction> Actions = new List<AlertAction>();

        public Alert(Sev sev, string kind, string title, string detail)
        {
            Severity = sev; Kind = kind; Title = title; Detail = detail;
        }
    }

    public interface IAlertSink { void Raise(Alert a); }

    /// <summary>One place every watcher reports to: history, log file, and the UI sink.</summary>
    public static class Hub
    {
        static readonly object gate = new object();
        public static readonly List<Alert> History = new List<Alert>();
        public static IAlertSink Sink;

        public static void Raise(Alert a)
        {
            lock (gate)
            {
                History.Add(a);
                if (History.Count > 500) History.RemoveAt(0);
            }
            Store.Log(a);
            IAlertSink s = Sink;
            if (s != null) { try { s.Raise(a); } catch { } }
        }

        public static Alert[] Snapshot() { lock (gate) { return History.ToArray(); } }
    }

    /// <summary>Config, allow-list and log, all under one folder.</summary>
    public static class Store
    {
        static readonly object gate = new object();
        public static string Dir
        {
            get
            {
                string d = Environment.GetEnvironmentVariable("NOBETCI_DIR");
                if (string.IsNullOrEmpty(d))
                    d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nobetci");
                Directory.CreateDirectory(d);
                return d;
            }
        }

        static string P(string name) { return Path.Combine(Dir, name); }

        // ---- config (key=value lines)
        public static string Get(string key, string def)
        {
            lock (gate)
            {
                try
                {
                    if (!File.Exists(P("config.ini"))) return def;
                    foreach (string line in File.ReadAllLines(P("config.ini")))
                    {
                        int i = line.IndexOf('=');
                        if (i > 0 && line.Substring(0, i).Trim() == key) return line.Substring(i + 1).Trim();
                    }
                }
                catch { }
                return def;
            }
        }

        public static void Set(string key, string value)
        {
            lock (gate)
            {
                Dictionary<string, string> d = new Dictionary<string, string>();
                try
                {
                    if (File.Exists(P("config.ini")))
                        foreach (string line in File.ReadAllLines(P("config.ini")))
                        {
                            int i = line.IndexOf('=');
                            if (i > 0) d[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
                        }
                }
                catch { }
                d[key] = value;
                StringBuilder sb = new StringBuilder();
                foreach (KeyValuePair<string, string> kv in d) sb.AppendLine(kv.Key + "=" + kv.Value);
                try { File.WriteAllText(P("config.ini"), sb.ToString()); } catch { }
            }
        }

        // ---- allow-list: sha256 of files the user said are fine
        static HashSet<string> allow;
        static void LoadAllow()
        {
            if (allow != null) return;
            allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(P("allow.txt")))
                    foreach (string line in File.ReadAllLines(P("allow.txt")))
                    {
                        string h = line.Split('\t')[0].Trim();
                        if (h.Length == 64) allow.Add(h);
                    }
            }
            catch { }
        }

        public static bool IsAllowed(string sha)
        {
            if (string.IsNullOrEmpty(sha)) return false;
            lock (gate) { LoadAllow(); return allow.Contains(sha); }
        }

        public static void Allow(string sha, string path)
        {
            if (string.IsNullOrEmpty(sha)) return;
            lock (gate)
            {
                LoadAllow();
                if (!allow.Add(sha)) return;
                try { File.AppendAllText(P("allow.txt"), sha + "\t" + path + "\t" + DateTime.Now.ToString("s") + Environment.NewLine); } catch { }
            }
        }

        // ---- baselines (autorun snapshot etc.)
        public static string ReadFile(string name) { try { return File.Exists(P(name)) ? File.ReadAllText(P(name)) : null; } catch { return null; } }
        public static void WriteFile(string name, string text) { lock (gate) { try { File.WriteAllText(P(name), text); } catch { } } }
        public static string PathOf(string name) { return P(name); }

        // ---- log
        public static void Log(Alert a)
        {
            lock (gate)
            {
                try
                {
                    string f = P("events.log");
                    if (File.Exists(f) && new FileInfo(f).Length > 2 * 1024 * 1024) File.Move(f, P("events.old.log"));
                    File.AppendAllText(f, a.Time.ToString("s") + "\t" + a.Severity + "\t" + a.Kind + "\t" + One(a.Title) + "\t" + One(a.Detail) + Environment.NewLine, Encoding.UTF8);
                }
                catch { }
            }
        }

        static string One(string s) { return (s ?? "").Replace("\r", " ").Replace("\n", " | ").Replace("\t", " "); }
    }

    public static class Settings
    {
        /// <summary>"ask" suspends a suspicious new process and asks; "monitor" only reports.</summary>
        public static string Mode
        {
            get { string m = Store.Get("mode", "monitor"); return m == "ask" ? "ask" : "monitor"; }
            set { Store.Set("mode", value == "ask" ? "ask" : "monitor"); }
        }

        /// <summary>Also treat unsigned programs started from user-writable folders as suspicious.</summary>
        public static bool Strict
        {
            get { return Store.Get("strict", "1") == "1"; }
            set { Store.Set("strict", value ? "1" : "0"); }
        }

        public static bool Paused;
    }
}
