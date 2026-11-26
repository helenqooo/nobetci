using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Nobetci
{
    /// <summary>Watches the things attackers switch off first: hosts file, firewall, Defender and its exclusions.</summary>
    public sealed class TamperGuard : IDisposable
    {
        public string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        public bool Dry;
        public int IntervalMs = 2000;

        Timer timer;
        int busy;
        string hostsBase;               // accepted content
        string hostsSeen;               // last content we reported (or accepted), to report once
        readonly Dictionary<string, int> fw = new Dictionary<string, int>();
        readonly Dictionary<string, int> av = new Dictionary<string, int>();
        readonly HashSet<string> exclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static readonly string[] FwProfiles = { "StandardProfile", "PublicProfile", "DomainProfile" };
        const string FwBase = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
        static readonly string[] ExclusionKeys =
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
        };

        public void Start()
        {
            hostsBase = Store.ReadFile("hosts.base");
            string cur = ReadHosts();
            if (hostsBase == null && cur != null) { hostsBase = cur; Store.WriteFile("hosts.base", cur); }
            hostsSeen = cur;

            foreach (string p in FwProfiles) fw[p] = FirewallValue(p);
            av["rtp"] = Dword(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
            av["spy"] = Dword(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");
            av["beh"] = Dword(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring");
            foreach (string e in Exclusions()) exclusions.Add(e);

            timer = new Timer(_ => Tick(), null, IntervalMs, IntervalMs);
        }

        public void Dispose() { if (timer != null) timer.Dispose(); }

        void Tick()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try { CheckHosts(); CheckFirewall(); CheckDefender(); }
            catch { }
            finally { Interlocked.Exchange(ref busy, 0); }
        }

        // ---------------------------------------------------------------- hosts

        string ReadHosts()
        {
            try { return File.Exists(HostsPath) ? File.ReadAllText(HostsPath) : null; } catch { return null; }
        }

        static HashSet<string> Lines(string text)
        {
            HashSet<string> s = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (text == null) return s;
            foreach (string raw in text.Split('\n'))
            {
                string l = raw.Trim();
                if (l.Length == 0 || l.StartsWith("#")) continue;
                s.Add(string.Join(" ", l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)));
            }
            return s;
        }

        void CheckHosts()
        {
            string cur = ReadHosts();
            if (cur == null || cur == hostsSeen) return;
            hostsSeen = cur;
            HashSet<string> b = Lines(hostsBase), c = Lines(cur);
            List<string> added = c.Where(x => !b.Contains(x)).ToList();
            List<string> removed = b.Where(x => !c.Contains(x)).ToList();
            if (added.Count == 0 && removed.Count == 0) return;   // comments or whitespace only

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("+" + added.Count + " satır eklendi, -" + removed.Count + " satır silindi.");
            foreach (string l in added.Take(6)) sb.AppendLine("+ " + l);
            foreach (string l in removed.Take(3)) sb.AppendLine("- " + l);
            sb.Append("Dosya: " + HostsPath);

            Alert a = new Alert(Sev.Danger, "hosts", "hosts dosyası değiştirildi", sb.ToString());
            string accepted = cur;
            if (!Dry) a.Actions.Add(new AlertAction("Geri al", () => { RestoreHosts(); a.Resolved = true; }));
            a.Actions.Add(new AlertAction("Kabul et", () => { hostsBase = accepted; Store.WriteFile("hosts.base", accepted); a.Resolved = true; }));
            Hub.Raise(a);
        }

        public bool RestoreHosts()
        {
            try
            {
                if (hostsBase == null) return false;
                try { File.SetAttributes(HostsPath, FileAttributes.Normal); } catch { }
                try { File.WriteAllText(HostsPath, hostsBase); }
                catch
                {
                    // someone changed the permissions: reset them, then write
                    Run("icacls.exe", "\"" + HostsPath + "\" /reset");
                    File.WriteAllText(HostsPath, hostsBase);
                }
                hostsSeen = hostsBase;
                return true;
            }
            catch { return false; }
        }

        // ---------------------------------------------------------------- firewall

        static int FirewallValue(string profile)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(FwBase + profile))
                {
                    object v = k == null ? null : k.GetValue("EnableFirewall");
                    return v == null ? -1 : Convert.ToInt32(v);
                }
            }
            catch { return -1; }
        }

        void CheckFirewall()
        {
            List<string> off = new List<string>();
            foreach (string p in FwProfiles)
            {
                int now = FirewallValue(p), was;
                fw.TryGetValue(p, out was);
                if (was == 1 && now == 0) off.Add(p.Replace("Profile", ""));
                fw[p] = now;
            }
            if (off.Count == 0) return;
            Alert a = new Alert(Sev.Danger, "firewall", "Windows Güvenlik Duvarı kapatıldı", "Kapanan profil: " + string.Join(", ", off) + ". Bunu sen yapmadıysan bir program yapmıştır.");
            if (!Dry) a.Actions.Add(new AlertAction("Geri aç", () => { Run("netsh.exe", "advfirewall set allprofiles state on"); a.Resolved = true; }));
            Hub.Raise(a);
        }

        // ---------------------------------------------------------------- Defender

        static int Dword(string sub, string name)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(sub))
                {
                    object v = k == null ? null : k.GetValue(name);
                    return v == null ? 0 : Convert.ToInt32(v);
                }
            }
            catch { return 0; }
        }

        static List<string> Exclusions()
        {
            List<string> l = new List<string>();
            foreach (string sub in ExclusionKeys)
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(sub))
                        if (k != null) foreach (string n in k.GetValueNames()) l.Add(sub.Substring(sub.LastIndexOf('\\') + 1) + ": " + n);
                }
                catch { }
            }
            return l;
        }

        void CheckDefender()
        {
            List<string> off = new List<string>();
            int rtp = Dword(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
            int spy = Dword(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");
            int beh = Dword(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring");
            if (av["rtp"] == 0 && rtp == 1) off.Add("gerçek zamanlı koruma");
            if (av["spy"] == 0 && spy == 1) off.Add("Defender (ilke ile)");
            if (av["beh"] == 0 && beh == 1) off.Add("davranış izleme");
            av["rtp"] = rtp; av["spy"] = spy; av["beh"] = beh;
            if (off.Count > 0)
                Hub.Raise(new Alert(Sev.Danger, "defender", "Windows Defender koruması kapatıldı", "Kapanan: " + string.Join(", ", off) + ". Bunu sen yapmadıysan bir program yapmıştır."));

            foreach (string ex in Exclusions())
            {
                if (!exclusions.Add(ex)) continue;
                string entry = ex;
                Alert a = new Alert(Sev.Danger, "defender", "Defender'a dışlama eklendi", entry + Environment.NewLine + "Dışlanan yerler antivirüs taramasından muaf olur; zararlılar bunu sık kullanır.");
                if (!Dry) a.Actions.Add(new AlertAction("Dışlamayı kaldır", () => { RemoveExclusion(entry); a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Bende kalsın", () => { a.Resolved = true; }));
                Hub.Raise(a);
            }
        }

        static void RemoveExclusion(string entry)
        {
            int i = entry.IndexOf(": ");
            if (i < 0) return;
            string kind = entry.Substring(0, i), name = entry.Substring(i + 2);
            string cmd = kind == "Paths" ? "Remove-MpPreference -ExclusionPath" : kind == "Extensions" ? "Remove-MpPreference -ExclusionExtension" : "Remove-MpPreference -ExclusionProcess";
            Run("powershell.exe", "-NoProfile -Command \"" + cmd + " '" + name.Replace("'", "''") + "'\"");
        }

        static void Run(string exe, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe, args);
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                using (Process p = Process.Start(psi)) { p.WaitForExit(10000); }
            }
            catch { }
        }
    }
}
