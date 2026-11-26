using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Nobetci
{
    public sealed class ScanResult
    {
        public string Path, Sha256, Publisher = "";
        public int Score;
        /// <summary>0 = nothing found, 1 = suspicious, 2 = malicious.</summary>
        public int Verdict;
        public bool Signed;
        /// <summary>A block-list or antimalware-engine hit: certain enough to act on without asking.</summary>
        public bool HardHit;
        public readonly List<string> Reasons = new List<string>();
        public string Summary() { return string.Join("; ", Reasons); }
        public string VerdictText { get { return Verdict == 2 ? "ZARARLI" : Verdict == 1 ? "ŞÜPHELİ" : "temiz"; } }
        internal void Add(int weight, string why) { Score += weight; Reasons.Add(why + " (+" + weight + ")"); }
    }

    /// <summary>Just enough of the PE format to judge a file: sections, entry point, imports, overlay.</summary>
    internal sealed class PeInfo
    {
        public class Section { public string Name; public uint VSize, VAddr, RawSize, RawPtr, Flags; public double Entropy; }

        public bool Valid, Is64, IsDll, IsDriver, IsDotNet;
        public int ImportCount;
        public int EntrySection = -1;
        public long OverlayOffset, OverlaySize;
        public readonly List<Section> Sections = new List<Section>();

        static uint U16(byte[] b, int n, long o) { return o < 0 || o + 2 > n ? 0u : (uint)(b[o] | b[o + 1] << 8); }
        static uint U32(byte[] b, int n, long o) { return o < 0 || o + 4 > n ? 0u : (uint)(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24); }

        long Offset(uint rva)
        {
            foreach (Section s in Sections)
                if (rva >= s.VAddr && rva < s.VAddr + Math.Max(s.VSize, s.RawSize)) return rva - s.VAddr + s.RawPtr;
            return -1;
        }

        public static PeInfo Parse(byte[] b, int n, long fileLength)
        {
            PeInfo pe = new PeInfo();
            if (n < 0x100 || b[0] != 'M' || b[1] != 'Z') return pe;
            long nt = U32(b, n, 0x3C);
            if (nt <= 0 || nt + 0x108 > n || U32(b, n, nt) != 0x00004550) return pe;
            int sections = (int)U16(b, n, nt + 6);
            int optSize = (int)U16(b, n, nt + 20);
            uint chars = U16(b, n, nt + 22);
            long opt = nt + 24;
            uint magic = U16(b, n, opt);
            if (magic != 0x10B && magic != 0x20B) return pe;
            pe.Is64 = magic == 0x20B;
            pe.IsDll = (chars & 0x2000) != 0;
            uint entry = U32(b, n, opt + 16);
            pe.IsDriver = U16(b, n, opt + 68) == 1;      // IMAGE_SUBSYSTEM_NATIVE
            long dirs = opt + (pe.Is64 ? 112 : 96);
            uint dirCount = U32(b, n, opt + (pe.Is64 ? 108 : 92));
            uint importRva = dirCount > 1 ? U32(b, n, dirs + 8) : 0;
            uint secOff = dirCount > 4 ? U32(b, n, dirs + 32) : 0, secSize = dirCount > 4 ? U32(b, n, dirs + 36) : 0;
            pe.IsDotNet = dirCount > 14 && U32(b, n, dirs + 14 * 8) != 0;

            long st = opt + optSize;
            long end = 0;
            for (int i = 0; i < sections && i < 96; i++)
            {
                long o = st + i * 40;
                if (o + 40 > n) break;
                Section s = new Section();
                int len = 0;
                while (len < 8 && b[o + len] != 0) len++;
                s.Name = Encoding.ASCII.GetString(b, (int)o, len);
                s.VSize = U32(b, n, o + 8); s.VAddr = U32(b, n, o + 12); s.RawSize = U32(b, n, o + 16); s.RawPtr = U32(b, n, o + 20); s.Flags = U32(b, n, o + 36);
                if (s.RawPtr > 0 && s.RawSize > 0)
                {
                    end = Math.Max(end, (long)s.RawPtr + s.RawSize);
                    long from = s.RawPtr, cnt = Math.Min(s.RawSize, Math.Max(0, n - from));
                    if (cnt > 0) s.Entropy = Entropy(b, (int)from, (int)cnt);
                }
                pe.Sections.Add(s);
            }
            if (pe.Sections.Count == 0) return pe;
            pe.Valid = true;

            for (int i = 0; i < pe.Sections.Count; i++)
            {
                Section s = pe.Sections[i];
                if (entry != 0 && entry >= s.VAddr && entry < s.VAddr + Math.Max(s.VSize, s.RawSize)) pe.EntrySection = i;
            }

            // what follows the last section, minus the certificate table, is the overlay
            long fileEnd = fileLength;
            if (secOff >= end && secOff + secSize <= fileLength && secSize > 0) fileEnd = secOff;
            if (end > 0 && fileEnd > end) { pe.OverlayOffset = end; pe.OverlaySize = fileEnd - end; }

            if (importRva != 0)
            {
                long d = pe.Offset(importRva);
                int step = pe.Is64 ? 8 : 4;
                for (int i = 0; d > 0 && i < 400 && d + 20 <= n; i++, d += 20)
                {
                    uint oft = U32(b, n, d), name = U32(b, n, d + 12), ft = U32(b, n, d + 16);
                    if (name == 0 && ft == 0) break;
                    long t = pe.Offset(oft != 0 ? oft : ft);
                    for (int k = 0; t > 0 && k < 4000 && t + step <= n; k++, t += step)
                    {
                        if (U32(b, n, t) == 0 && (step == 4 || U32(b, n, t + 4) == 0)) break;
                        pe.ImportCount++;
                    }
                }
            }
            return pe;
        }

        public static double Entropy(byte[] b, int from, int count)
        {
            if (count <= 0) return 0;
            int[] c = new int[256];
            for (int i = 0; i < count; i++) c[b[from + i]]++;
            double h = 0;
            for (int i = 0; i < 256; i++)
            {
                if (c[i] == 0) continue;
                double p = (double)c[i] / count;
                h -= p * Math.Log(p, 2);
            }
            return h;
        }
    }

    /// <summary>The Windows antimalware interface: asks whatever engine is installed (Defender, normally) about a buffer.</summary>
    internal static class Amsi
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiInitialize(string appName, out IntPtr context);
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

        static readonly object gate = new object();
        static IntPtr ctx;
        static bool tried;

        public static bool Available
        {
            get
            {
                lock (gate)
                {
                    if (!tried)
                    {
                        tried = true;
                        try { if (AmsiInitialize("Nobetci", out ctx) != 0) ctx = IntPtr.Zero; } catch { ctx = IntPtr.Zero; }
                    }
                    return ctx != IntPtr.Zero;
                }
            }
        }

        /// <summary>true = the engine calls it malware, false = not, null = no engine answered.</summary>
        public static bool? IsMalware(byte[] buf, int len, string name)
        {
            if (!Available || len <= 0) return null;
            try
            {
                int result;
                if (AmsiScanBuffer(ctx, buf, (uint)len, name ?? "file", IntPtr.Zero, out result) != 0) return null;
                return result >= 32768;     // AMSI_RESULT_DETECTED
            }
            catch { return null; }
        }
    }

    /// <summary>Signed-but-exploitable drivers that malware brings along to kill security software from the kernel (BYOVD).</summary>
    internal static class Drivers
    {
        static readonly HashSet<string> Names = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "rtcore64.sys", "rtcore32.sys", "iobitunlocker.sys", "gdrv.sys", "dbutil_2_3.sys", "dbutildrv2.sys", "mhyprot2.sys", "mhyprot3.sys",
            "winring0x64.sys", "winring0.sys", "kprocesshacker.sys", "procexp152.sys", "truesight.sys", "zamguard64.sys", "zam64.sys", "capcom.sys",
            "aswarpot.sys", "eneio64.sys", "enetechio64.sys", "asrdrv101.sys", "asrdrv102.sys", "asrdrv103.sys", "asio64.sys", "asio32.sys", "gmer64.sys",
            "speedfan.sys", "cpuz141.sys", "physmem.sys", "winio64.sys", "atillk64.sys", "nicm.sys", "bs_def64.sys", "amifldrv64.sys", "pchunter.sys",
            "blackbonedrv10.sys", "viragt64.sys", "elrawdsk.sys", "ksapi64.sys", "terminator.sys", "wantd.sys", "hwrwdrv.sys", "inpoutx64.sys"
        };
        static readonly object gate = new object();
        static HashSet<string> hashes;
        static DateTime loadedStamp;
        const string ListFile = "loldrivers.txt";
        const string Feed = "https://www.loldrivers.io/api/drivers.csv";

        public static int HashCount { get { Load(); lock (gate) return hashes.Count; } }

        static void Load()
        {
            lock (gate)
            {
                string f = Store.PathOf(ListFile);
                DateTime stamp = File.Exists(f) ? File.GetLastWriteTimeUtc(f) : DateTime.MinValue;
                if (hashes != null && stamp == loadedStamp) return;
                hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                loadedStamp = stamp;
                try { if (File.Exists(f)) foreach (string l in File.ReadAllLines(f)) if (l.Length == 64) hashes.Add(l); } catch { }
            }
        }

        /// <summary>Why this driver is on the list, or null.</summary>
        public static string Check(string path, string sha)
        {
            string name = "";
            try { name = System.IO.Path.GetFileName(path); } catch { }
            Load();
            if (sha != null) lock (gate) if (hashes.Contains(sha)) return "Özeti loldrivers.io listesindeki zafiyetli sürücülerden biriyle aynı";
            if (Names.Contains(name)) return "Adı, güvenlik yazılımlarını kapatmak için kötüye kullanılan bilinen bir sürücüyle aynı (" + name + ")";
            return null;
        }

        public static bool KnownName(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            string l = text.ToLowerInvariant();
            foreach (string n in Names) if (l.Contains(n)) return true;
            return false;
        }

        /// <summary>Every SHA-256 in the feed (64 hex digits standing alone).</summary>
        public static List<string> ParseCsv(string csv)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in Regex.Matches(csv ?? "", @"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")) set.Add(m.Value.ToLowerInvariant());
            return set.ToList();
        }

        /// <summary>Downloads the vulnerable-driver list. Returns how many hashes it now holds, -1 on failure.</summary>
        public static int Update(int timeoutSeconds)
        {
            try
            {
                using (HttpClient http = new HttpClient())
                {
                    http.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
                    http.DefaultRequestHeaders.UserAgent.ParseAdd("Nobetci/1.0");
                    string csv = http.GetStringAsync(Feed).GetAwaiter().GetResult();
                    List<string> list = ParseCsv(csv);
                    if (list.Count < 100) return -1;        // a truncated or changed feed must not wipe a good list
                    File.WriteAllLines(Store.PathOf(ListFile), list);
                    Load();
                    return list.Count;
                }
            }
            catch { return -1; }
        }

        public static void UpdateIfStale()
        {
            try
            {
                string f = Store.PathOf(ListFile);
                if (File.Exists(f) && (DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalDays < 7) return;
                Update(30);
            }
            catch { }
        }
    }

    /// <summary>Files taken out of harm's way: stored scrambled so nothing can run them, with a note of where they came from.</summary>
    public static class Quarantine
    {
        public static string Dir { get { string d = System.IO.Path.Combine(Store.Dir, "quarantine"); Directory.CreateDirectory(d); return d; } }

        static void Flip(byte[] b) { for (int i = 0; i < b.Length; i++) b[i] ^= 0xA5; }

        /// <summary>Moves the file into quarantine. Returns its id (the SHA-256), or null if it could not be moved.</summary>
        public static string Put(string path, string reason)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                string id;
                using (SHA256 sha = SHA256.Create()) id = string.Concat(sha.ComputeHash(data).Select(x => x.ToString("x2")));
                Flip(data);
                File.WriteAllBytes(System.IO.Path.Combine(Dir, id + ".q"), data);
                File.WriteAllText(System.IO.Path.Combine(Dir, id + ".txt"), path + Environment.NewLine + DateTime.Now.ToString("s") + Environment.NewLine + (reason ?? ""), Encoding.UTF8);
                try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
                File.Delete(path);
                return id;
            }
            catch { return null; }
        }

        public static string OriginalPath(string id)
        {
            try { return File.ReadAllLines(System.IO.Path.Combine(Dir, id + ".txt"))[0]; } catch { return null; }
        }

        /// <summary>Puts a quarantined file back where it was (or at <paramref name="to"/>).</summary>
        public static bool Restore(string id, string to)
        {
            try
            {
                string q = System.IO.Path.Combine(Dir, id + ".q");
                to = to ?? OriginalPath(id);
                if (to == null || !File.Exists(q)) return false;
                byte[] data = File.ReadAllBytes(q);
                Flip(data);
                File.WriteAllBytes(to, data);
                File.Delete(q);
                try { File.Delete(System.IO.Path.Combine(Dir, id + ".txt")); } catch { }
                return true;
            }
            catch { return false; }
        }
    }

    /// <summary>
    /// Static file analysis. No signature database: it reads what a file is able to do (APIs, strings, structure),
    /// scores that, and asks the installed antimalware engine for a second opinion.
    /// </summary>
    public static class Scanner
    {
        public const int MaliciousAt = 70, SuspiciousAt = 40;
        const int MaxRead = 24 * 1024 * 1024;

        sealed class Group { public string[] Kw; public int Min; }
        sealed class Rule { public string Name; public int Weight; public Group[] Groups; }

        static Group Any(int min, params string[] kw) { return new Group { Kw = kw, Min = min }; }
        static Rule R(string name, int weight, params Group[] g) { return new Rule { Name = name, Weight = weight, Groups = g }; }

        // keywords are matched against the file's printable strings, lower-cased
        static readonly Rule[] BuiltIn =
        {
            R("Tuş kaydı yapabilir (klavye kancası + tuş okuma)", 15, Any(1, "setwindowshookex"), Any(2, "getasynckeystate", "getkeyboardstate", "getkeystate", "mapvirtualkey", "tounicodeex", "getkeynametext", "getforegroundwindow")),
            R("Ham klavye girdisini okuyabilir", 10, Any(1, "registerrawinputdevices"), Any(1, "getrawinputdata"), Any(1, "getforegroundwindow", "getwindowtext")),
            R("Ekran görüntüsü alabilir", 8, Any(1, "bitblt", "copyfromscreen", "printwindow", "idxgioutputduplication"), Any(1, "getdc", "getwindowdc", "createcompatiblebitmap", "getdesktopwindow", "copyfromscreen", "idxgioutputduplication")),
            R("Başka işlemlere kod enjekte edebilir", 25, Any(1, "writeprocessmemory", "ntwritevirtualmemory"), Any(1, "createremotethread", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "setthreadcontext"), Any(1, "virtualallocex", "ntallocatevirtualmemory", "ntmapviewofsection")),
            R("İşlem oyma (process hollowing) kalıbı", 35, Any(1, "ntunmapviewofsection", "zwunmapviewofsection"), Any(1, "setthreadcontext", "ntsetcontextthread"), Any(1, "writeprocessmemory", "ntwritevirtualmemory")),
            R("Sanal makine / analiz aracı arıyor", 20, Any(3, "vmtoolsd", "vboxservice", "vboxguest", "sbiedll", "wireshark", "procmon", "x64dbg", "ollydbg", "ida64", "processhacker", "sandboxie", "vboxminirdr", "fiddler", "dnspy", "cuckoo", "vmwareuser", "qemu-ga", "joeboxserver", "prl_tools")),
            R("Tarayıcı parolalarına / kripto cüzdanlarına erişiyor", 30, Any(2, "login data", "logins.json", "key4.db", "cookies.sqlite", "wallet.dat", "nkbihfbeogaeaoehlefnkodbefgpgknn", "encrypted_key", "os_crypt", "moz_logins", "\\tdata", "exodus.wallet", "electrum\\wallets", "ethereum\\keystore", "local storage\\leveldb", "recentservers.xml", "\\user data\\", "web data")),
            R("Çok sayıda parola / cüzdan deposunu hedefliyor", 15, Any(4, "login data", "logins.json", "key4.db", "cookies.sqlite", "wallet.dat", "nkbihfbeogaeaoehlefnkodbefgpgknn", "encrypted_key", "os_crypt", "moz_logins", "\\tdata", "exodus.wallet", "electrum\\wallets", "ethereum\\keystore", "local storage\\leveldb", "recentservers.xml", "\\user data\\", "web data")),
            R("Veri sızdırma kanalı içeriyor (Telegram botu, Discord webhook, dosya paylaşımı)", 20, Any(1, "api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "pastebin.com/raw", "transfer.sh", "anonfiles.com", "gofile.io/upload", "0x0.st", "catbox.moe/user/api")),
            R("Dış IP adresini soruyor", 5, Any(1, "api.ipify.org", "ip-api.com", "ipinfo.io", "checkip.amazonaws.com", "icanhazip.com", "ifconfig.me")),
            R("Defender / güvenlik duvarı ayarlarına dokunuyor", 20, Any(1, "disableantispyware", "disablerealtimemonitoring", "set-mppreference", "add-mppreference", "disablebehaviormonitoring", "netsh advfirewall set", "advfirewall firewall add", "disableantivirus", "sc stop windefend", "tamperprotection")),
            R("Defender'ı birden çok yoldan kapatmaya çalışıyor", 15, Any(3, "disableantispyware", "disablerealtimemonitoring", "set-mppreference", "add-mppreference", "disablebehaviormonitoring", "netsh advfirewall set", "disableantivirus", "sc stop windefend", "tamperprotection", "exclusionpath", "disableioavprotection", "smartscreenenabled")),
            R("hosts dosyasına erişiyor", 10, Any(1, "drivers\\etc\\hosts", "drivers/etc/hosts")),
            R("Yedekleri / gölge kopyaları siliyor (fidye yazılımı)", 40, Any(1, "vssadmin delete shadows", "vssadmin.exe delete shadows", "wbadmin delete catalog", "recoveryenabled no", "shadowcopy delete", "bootstatuspolicy ignoreallfailures", "delete shadows /all")),
            R("Fidye notu ifadeleri içeriyor", 15, Any(2, "your files have been encrypted", "files are encrypted", "decrypt your files", "bitcoin", ".onion", "restore your files", "readme_decrypt", "how_to_decrypt", "tor browser", "pay the ransom", "decryption key")),
            R("İndirip çalıştırabilir", 10, Any(1, "urldownloadtofile", "downloadstring", "downloadfile", "invoke-webrequest", "bitsadmin /transfer", "certutil -urlcache", "winhttp.winhttprequest", "msxml2.xmlhttp"), Any(1, "shellexecute", "createprocess", "winexec", "process.start", "invoke-expression", "start-process", "wscript.shell")),
            R("Kendini kalıcı yapabilir (Run anahtarı, görev, başlangıç)", 8, Any(1, "currentversion\\run", "schtasks /create", "image file execution options", "winlogon\\shell", "appinit_dlls", "\\programs\\startup")),
            R("Bilinen zafiyetli sürücü adı içeriyor (BYOVD)", 35, Any(1, "rtcore64", "iobitunlocker", "gdrv.sys", "dbutil_2_3", "mhyprot", "winring0", "kprocesshacker", "procexp152", "truesight.sys", "zamguard", "zam64.sys", "capcom.sys", "aswarpot", "eneio64", "asrdrv10", "gmer64")),
            R("Çekirdek sürücüsü yükleyebilir", 10, Any(1, "ntloaddriver", "zwloaddriver")),
            R("Güvenlik yazılımı işlemlerini sonlandırmaya çalışıyor", 25, Any(2, "msmpeng.exe", "avp.exe", "avgnt.exe", "avastsvc", "ekrn.exe", "bdagent", "mbamservice", "sophos", "mcshield", "windefend", "nortonsecurity", "securityhealthservice"), Any(1, "terminateprocess", "taskkill", "zwterminateprocess", "ntterminateprocess")),
            R("UAC atlatma kalıbı", 20, Any(1, "fodhelper", "eventvwr.exe", "sdclt.exe", "computerdefaults", "cmstp"), Any(1, "shell\\open\\command", "delegateexecute")),
            R("LSASS belleğinden kimlik bilgisi çekebilir", 35, Any(1, "lsass"), Any(1, "minidumpwritedump", "sekurlsa", "comsvcs.dll")),
            R("Bilinen saldırı aracı / zararlı yazılım ailesi adı içeriyor", 40, Any(1, "mimikatz", "sekurlsa::", "lsadump::", "asyncrat", "quasarrat", "njrat", "darkcomet", "nanocore", "remcos", "redline stealer", "redlinestealer", "redline.stealer", "lummac2", "stealerium", "xworm", "venomrat", "dcrat.", "dcrat_", "dcrat-", "dcrat client", "cobaltstrike", "meterpreter")),
            R("AMSI / ETW yamasıyla izlemeyi kör etmeye çalışıyor", 30, Any(1, "amsiscanbuffer", "etweventwrite", "amsiutils", "amsiinitfailed"), Any(1, "virtualprotect", "writeprocessmemory", "ntprotectvirtualmemory")),
            R("Kripto madenci izleri", 30, Any(2, "stratum+tcp", "xmrig", "--donate-level", "pool.minexmr", "nicehash", "randomx", "cryptonight")),
            R(".NET karartıcı izleri (kod bilerek okunmaz yapılmış)", 15, Any(1, "confusedbyattribute", "confuserex", "smartassembly", ".net reactor", "bitmono", "koivm", "dnguard", "eazfuscator", "babelobfuscator", "obfuscar")),
        };

        static Rule[] userRules;
        static DateTime userStamp;

        /// <summary>
        /// Extra rules from rules.txt in the data folder, one per line: <c>ad|puan|all|kelime1,kelime2</c> (all words needed)
        /// or <c>ad|puan|any:2|kelime1,kelime2,kelime3</c> (at least two of them).
        /// </summary>
        static Rule[] UserRules()
        {
            try
            {
                string f = Store.PathOf("rules.txt");
                if (!File.Exists(f)) return new Rule[0];
                DateTime stamp = File.GetLastWriteTimeUtc(f);
                if (userRules != null && stamp == userStamp) return userRules;
                userRules = ParseRules(File.ReadAllText(f));
                userStamp = stamp;
                return userRules;
            }
            catch { return new Rule[0]; }
        }

        static Rule[] ParseRules(string text)
        {
            List<Rule> list = new List<Rule>();
            foreach (string raw in (text ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                string[] p = line.Split('|');
                int w;
                if (p.Length < 4 || !int.TryParse(p[1].Trim(), out w)) continue;
                string[] kw = p[3].Split(',').Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 1).ToArray();
                if (kw.Length == 0) continue;
                string mode = p[2].Trim().ToLowerInvariant();
                int min = kw.Length;
                if (mode.StartsWith("any")) { min = 1; int c = mode.IndexOf(':'); if (c > 0) int.TryParse(mode.Substring(c + 1), out min); if (min < 1) min = 1; }
                list.Add(R(p[0].Trim(), Math.Max(0, Math.Min(100, w)), Any(min, kw)));
            }
            return list.ToArray();
        }

        static bool Matches(Rule r, string blob)
        {
            foreach (Group g in r.Groups)
            {
                int hits = 0;
                foreach (string k in g.Kw)
                {
                    if (blob.IndexOf(k, StringComparison.Ordinal) >= 0 && ++hits >= g.Min) break;
                }
                if (hits < g.Min) return false;
            }
            return true;
        }

        /// <summary>Every run of 5+ printable characters (ASCII and UTF-16), lower-cased, one per line.</summary>
        internal static string Strings(byte[] b, int n)
        {
            StringBuilder sb = new StringBuilder(Math.Min(n / 4 + 64, 4 * 1024 * 1024));
            char[] tmp = new char[512];
            int len = 0;
            for (int i = 0; i <= n; i++)
            {
                byte c = i < n ? b[i] : (byte)0;
                if (c >= 0x20 && c < 0x7F)
                {
                    if (len == tmp.Length) { sb.Append(tmp, 0, len); len = 0; tmp[len++] = '\u0001'; }
                    tmp[len++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
                }
                else
                {
                    if (len >= 5) { sb.Append(tmp, 0, len).Append('\n'); }
                    len = 0;
                }
            }
            len = 0;
            for (int i = 0; i + 1 <= n; i += 2)
            {
                byte c = i + 1 < n ? b[i] : (byte)0, hi = i + 1 < n ? b[i + 1] : (byte)1;
                if (hi == 0 && c >= 0x20 && c < 0x7F)
                {
                    if (len == tmp.Length) { sb.Append(tmp, 0, len); len = 0; tmp[len++] = '\u0001'; }
                    tmp[len++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
                }
                else
                {
                    if (len >= 5) { sb.Append(tmp, 0, len).Append('\n'); }
                    len = 0;
                }
            }
            return sb.Replace("\u0001", "").ToString();
        }

        static readonly HashSet<string> ScriptExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta" };
        static readonly HashSet<string> ScanExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".ocx", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta" };
        static readonly HashSet<string> SystemNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe", "services.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "runtimebroker.exe", "wininit.exe" };
        static readonly Regex DoubleExt = new Regex(@"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Dictionary<string, int> PackerSections = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "UPX0", 15 }, { "UPX1", 15 }, { ".aspack", 15 }, { ".MPRESS1", 15 }, { ".petite", 15 }, { ".nsp0", 15 }, { ".packed", 15 },
            { ".vmp0", 20 }, { ".vmp1", 20 }, { ".themida", 20 }, { ".winlice", 20 }, { ".enigma1", 20 }, { ".enigma2", 20 }
        };

        public static bool IsScannable(string path)
        {
            try { return ScanExt.Contains(System.IO.Path.GetExtension(path)); } catch { return false; }
        }

        static string Decode(byte[] b, int n)
        {
            if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, n - 2);
            if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return Encoding.UTF8.GetString(b, 3, n - 3);
            return Encoding.UTF8.GetString(b, 0, n);
        }

        /// <summary>The scoring itself, on bytes already in memory (the self-test feeds it synthetic files).</summary>
        public static ScanResult Analyze(string path, byte[] b, int n, long fileLength)
        {
            ScanResult r = Content(path, b, n, fileLength);
            NameChecks(path, r);
            return r;
        }

        // Windows tools that run whatever they are handed: a copy outside Windows hides who is really doing the work
        static readonly HashSet<string> LolBins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe" };

        /// <summary>
        /// What the file calls itself and where it sits. A valid signature does not excuse these:
        /// a genuine Windows file under a false name or in a false place is the trick itself.
        /// </summary>
        static void NameChecks(string path, ScanResult r)
        {
            string name = "";
            try { name = System.IO.Path.GetFileName(path); } catch { }
            if (DoubleExt.IsMatch(name) || name.IndexOf('‮') >= 0) r.Add(30, "Çift uzantı: belge gibi görünmeye çalışan çalıştırılabilir dosya");
            if (Rules.IsSystemLocation(path)) return;
            if (SystemNames.Contains(name)) r.Add(40, "Windows sistem dosyasının adını taşıyor ama Windows klasöründe değil");
            else if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                string orig = Procs.OriginalName(path);
                if (LolBins.Contains(orig))
                {
                    bool renamed = !orig.Equals(name, StringComparison.OrdinalIgnoreCase);
                    r.Add(renamed ? 40 : 25, "Windows aracının (" + orig + ") kopyası, Windows klasörü dışında" + (renamed ? " ve başka bir adla" : ""));
                }
            }
        }

        /// <summary>What the bytes are able to do.</summary>
        static ScanResult Content(string path, byte[] b, int n, long fileLength)
        {
            ScanResult r = new ScanResult { Path = path };
            string name = "", ext = "";
            try { name = System.IO.Path.GetFileName(path); ext = System.IO.Path.GetExtension(path); } catch { }
            bool script = ScriptExt.Contains(ext);

            string blob = script ? Decode(b, n).ToLowerInvariant() : Strings(b, n);
            foreach (Rule rule in BuiltIn) if (Matches(rule, blob)) r.Add(rule.Weight, rule.Name);
            foreach (Rule rule in UserRules()) if (Matches(rule, blob)) r.Add(rule.Weight, rule.Name);

            if (script)
            {
                // a script is a list of commands: the command-line rules apply to every line of it
                HashSet<string> seen = new HashSet<string>();
                int lines = 0;
                foreach (string raw in blob.Split('\n'))
                {
                    if (++lines > 4000) break;
                    string line = raw.Trim();
                    if (line.Length < 6 || line.Length > 4000) continue;
                    foreach (Finding f in Rules.CheckCommandLine(line))
                        if (f.Severity >= Sev.Warn && seen.Add(f.Code) && seen.Count <= 4) r.Add(f.Severity == Sev.Danger ? 55 : 20, f.Text);
                }
            }
            else
            {
                PeInfo pe = PeInfo.Parse(b, n, fileLength);
                if (pe.Valid)
                {
                    int pack = 0; string packName = null;
                    foreach (PeInfo.Section s in pe.Sections)
                    {
                        int w;
                        if (PackerSections.TryGetValue(s.Name, out w) && w > pack) { pack = w; packName = s.Name; }
                    }
                    if (pack > 0) r.Add(pack, "Paketleyici / koruyucu ile sarılmış (" + packName + " bölümü)");

                    bool hot = pe.Sections.Any(s => (s.Flags & 0x20000000) != 0 && s.RawSize >= 4096 && s.Entropy > 7.2);
                    if (pack == 0 && hot && !pe.IsDotNet && pe.ImportCount < 12)
                        r.Add(20, "Kodu sıkıştırılmış ya da şifrelenmiş (yüksek entropi, neredeyse hiç içe aktarım yok)");

                    if (!pe.IsDotNet && pe.Sections.Count > 1 && pe.EntrySection >= 0)
                    {
                        PeInfo.Section es = pe.Sections[pe.EntrySection];
                        if ((es.Flags & 0x80000000) != 0) r.Add(10, "Giriş noktası yazılabilir bir bölümde (kendini açan kod)");
                        else if (pe.EntrySection == pe.Sections.Count - 1 && pe.Sections.Count > 2) r.Add(10, "Giriş noktası son bölümde (sonradan eklenmiş kod olabilir)");
                    }

                    if (pe.OverlaySize > 256 * 1024 && pe.OverlaySize > fileLength / 2 && pe.OverlayOffset < n)
                    {
                        int cnt = (int)Math.Min(64 * 1024, n - pe.OverlayOffset);
                        if (cnt > 4096 && PeInfo.Entropy(b, (int)pe.OverlayOffset, cnt) > 7.4) r.Add(10, "Dosyanın çoğu, sonuna eklenmiş şifreli / sıkıştırılmış veri");
                    }
                }
            }

            return r;
        }

        // ---------------------------------------------------------------- block list

        static HashSet<string> block;
        static DateTime blockStamp;
        static readonly object gate = new object();

        static bool Blocked(string sha)
        {
            if (sha == null) return false;
            lock (gate)
            {
                try
                {
                    string f = Store.PathOf("block.txt");
                    DateTime stamp = File.Exists(f) ? File.GetLastWriteTimeUtc(f) : DateTime.MinValue;
                    if (block == null || stamp != blockStamp)
                    {
                        block = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        blockStamp = stamp;
                        if (File.Exists(f))
                            foreach (string l in File.ReadAllLines(f))
                            {
                                string h = l.Split('\t', ' ', ',', ';')[0].Trim();
                                if (h.Length == 64) block.Add(h);
                            }
                    }
                }
                catch { }
                return block != null && block.Contains(sha);
            }
        }

        /// <summary>Adds a SHA-256 to block.txt: that file is called malicious wherever it turns up.</summary>
        public static void Block(string sha, string note)
        {
            if (string.IsNullOrEmpty(sha) || sha.Length != 64) return;
            lock (gate) { try { File.AppendAllText(Store.PathOf("block.txt"), sha + "\t" + (note ?? "") + Environment.NewLine); } catch { } }
        }

        // ---------------------------------------------------------------- files

        sealed class Cached { public ScanResult R; public DateTime At; }
        static readonly Dictionary<string, Cached> cache = new Dictionary<string, Cached>(StringComparer.OrdinalIgnoreCase);

        public static void ForgetCache() { lock (cache) cache.Clear(); }

        /// <summary>Full verdict for a file on disk. Never throws; an unreadable file comes back clean with a note.</summary>
        public static ScanResult ScanFile(string path)
        {
            string key;
            FileInfo fi;
            try { fi = new FileInfo(path); key = path + "|" + fi.LastWriteTimeUtc.Ticks + "|" + fi.Length; }
            catch { return new ScanResult { Path = path }; }
            lock (cache)
            {
                Cached c;
                if (cache.TryGetValue(key, out c) && (DateTime.UtcNow - c.At).TotalMinutes < 30) return c.R;
            }

            ScanResult r;
            try { r = ScanFileCore(path, fi.Length); }
            catch (Exception ex) { r = new ScanResult { Path = path }; r.Reasons.Add("okunamadı: " + ex.Message); }
            lock (cache)
            {
                if (cache.Count > 3000) cache.Clear();
                cache[key] = new Cached { R = r, At = DateTime.UtcNow };
            }
            return r;
        }

        static readonly string OwnDir = AppContext.BaseDirectory.TrimEnd('\\') + "\\";

        // where the time goes (summed over worker threads): hash, signature, content analysis, antimalware engine
        static long tHash, tSig, tContent, tAmsi;
        static long Lap(ref long total, long since) { long now = Stopwatch.GetTimestamp(); Interlocked.Add(ref total, now - since); return now; }
        public static string Timing()
        {
            Func<long, string> s = t => (t / (double)Stopwatch.Frequency).ToString("0.0");
            return "özet " + s(tHash) + " sn, imza " + s(tSig) + " sn, içerik " + s(tContent) + " sn, AMSI " + s(tAmsi) + " sn";
        }

        static ScanResult ScanFileCore(string path, long length)
        {
            // our own rule tables would trip every rule
            if (path.StartsWith(OwnDir, StringComparison.OrdinalIgnoreCase)) return new ScanResult { Path = path };
            long t = Stopwatch.GetTimestamp();
            string sha = Procs.Sha256(path);
            t = Lap(ref tHash, t);
            if (Store.IsAllowed(sha)) return new ScanResult { Path = path, Sha256 = sha };

            SigInfo sig = Sig.Check(path);
            t = Lap(ref tSig, t);
            bool blocked = Blocked(sha);
            string ext = "";
            try { ext = System.IO.Path.GetExtension(path); } catch { }

            byte[] buf = null; int n = 0;
            ScanResult r;
            // a valid signature and no block-list hit: the content is the publisher's responsibility, skip the deep look
            if (sig.Signed && !blocked && !ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)) r = new ScanResult { Path = path };
            else
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    buf = new byte[(int)Math.Min(length, MaxRead)];
                    while (n < buf.Length) { int got = fs.Read(buf, n, buf.Length - n); if (got <= 0) break; n += got; }
                }
                r = Content(path, buf, n, length);
            }
            t = Lap(ref tContent, t);
            r.Sha256 = sha; r.Signed = sig.Signed; r.Publisher = sig.Publisher;

            // a signature is not a pardon, but it makes capability alone weak evidence
            if (sig.Signed && r.Score > 0) { r.Score = (int)(r.Score * 0.3); r.Reasons.Add("geçerli imza (" + sig.Publisher + "): puan düşürüldü"); }
            // only an administrator can put a file under Windows or Program Files: capability alone counts for less there too
            else if (r.Score > 0 && Rules.IsSystemLocation(path) && !Rules.IsUserWritable(path)) { r.Score = (int)(r.Score * 0.6); r.Reasons.Add("yalnızca yöneticinin yazabildiği klasörde kurulu: puan düşürüldü"); }
            // the name tricks are judged at full weight, signed or not
            NameChecks(path, r);

            if (blocked) { r.HardHit = true; r.Score = 100; r.Reasons.Insert(0, "Kara listede (block.txt)"); }

            bool driver = ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
            if (driver || (buf != null && PeInfo.Parse(buf, Math.Min(n, 4096), length).IsDriver))
            {
                string why = Drivers.Check(path, sha);
                if (why != null && sig.Catalog && InDriverStore(path))
                {
                    // shipped with Windows and only stored, not loaded: worth knowing about, not worth quarantining a piece of the system
                    r.Score = Math.Max(r.Score, 45); r.Reasons.Insert(0, why);
                    r.Reasons.Add("Windows'un kendi sürücü deposunda duruyor ve Windows kataloğunda kayıtlı: yüklenmedikçe zararsız, karantinaya alınmaz");
                }
                else if (why != null) { r.HardHit = true; r.Score = Math.Max(r.Score, 90); r.Reasons.Insert(0, why); }
            }

            if (buf != null && n > 0 && !r.HardHit)
            {
                bool? bad = Amsi.IsMalware(buf, n, path);
                if (bad != true && ScriptExt.Contains(ext))
                {
                    // script engines hand AMSI UTF-16 text, and that is the form its signatures are written for
                    byte[] wide = Encoding.Unicode.GetBytes(Decode(buf, n));
                    bad = Amsi.IsMalware(wide, wide.Length, path) ?? bad;
                }
                if (bad == true) { r.HardHit = true; r.Score = 100; r.Reasons.Insert(0, "Antimalware motoru (AMSI) zararlı olarak tanıdı"); }
                Lap(ref tAmsi, t);
            }

            if (r.Score > 100) r.Score = 100;
            r.Verdict = r.Score >= MaliciousAt ? 2 : r.Score >= SuspiciousAt ? 1 : 0;
            return r;
        }

        static readonly string DriverStore = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "DriverStore", "FileRepository") + "\\";
        static bool InDriverStore(string path) { return path.StartsWith(DriverStore, StringComparison.OrdinalIgnoreCase); }
    }

    /// <summary>
    /// The scanning side of the engine: checks executables and scripts as they are dropped into user-writable folders,
    /// and runs on-demand scans of a file or a folder.
    /// </summary>
    public sealed class ScanService : IDisposable
    {
        sealed class Pending { public string Path; public int Pid; public DateTime Due; }

        readonly Dictionary<string, Pending> pending = new Dictionary<string, Pending>();
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        readonly int self = Process.GetCurrentProcess().Id;
        readonly string ownDir = AppContext.BaseDirectory.TrimEnd('\\').ToLowerInvariant() + "\\";
        Thread worker;
        volatile bool stop;

        public bool Dry;
        public static ScanService Current;

        static readonly string[] Skip = { @"\node_modules\", @"\.git\", @"\site-packages\", @"\.vscode\", @"\npm-cache\", @"\.nuget\", @"\.dotnet\", @"\nobetci\quarantine\", @"\__pycache__\", @"\windows\winsxs\", @"\windows\servicing\", @"\windows\softwaredistribution\" };

        public void Start()
        {
            Current = this;
            worker = new Thread(Loop);
            worker.IsBackground = true;
            worker.Priority = ThreadPriority.BelowNormal;
            worker.Name = "scan";
            worker.Start();
            if (!Dry) ThreadPool.QueueUserWorkItem(_ => Drivers.UpdateIfStale());
        }

        /// <summary>Runs on the ETW thread for every file event, so it only filters and queues.</summary>
        public void OnFile(FileEvent e)
        {
            if (e.Op != "write" || e.Pid == self) return;
            string p = e.Path;
            if (string.IsNullOrEmpty(p)) return;
            int dot = p.LastIndexOf('.');
            if (dot < 0 || p.Length - dot > 5 || !Scanner.IsScannable(p)) return;
            string lp = p.ToLowerInvariant();
            if (!Rules.IsUserWritable(lp) && !lp.Contains(@"\drivers\")) return;
            if (lp.StartsWith(ownDir)) return;
            foreach (string s in Skip) if (lp.Contains(s)) return;
            lock (pending)
            {
                Pending x;
                if (!pending.TryGetValue(lp, out x))
                {
                    if (pending.Count > 300) return;
                    pending[lp] = x = new Pending { Path = p };
                }
                x.Pid = e.Pid;
                // wait until the writer has been quiet for two seconds: the file is still being written
                x.Due = DateTime.UtcNow.AddSeconds(2);
            }
        }

        void Loop()
        {
            while (!stop)
            {
                Thread.Sleep(400);
                List<Pending> due = null;
                lock (pending)
                {
                    DateTime now = DateTime.UtcNow;
                    foreach (KeyValuePair<string, Pending> kv in pending)
                        if (kv.Value.Due <= now) (due ?? (due = new List<Pending>())).Add(kv.Value);
                    if (due != null) foreach (Pending x in due) pending.Remove(x.Path.ToLowerInvariant());
                }
                if (due == null) continue;
                foreach (Pending x in due)
                {
                    try
                    {
                        if (!File.Exists(x.Path)) continue;
                        ScanResult r = Scanner.ScanFile(x.Path);
                        if (r.Verdict > 0) Report(r, x.Pid, "bırakıldı");
                    }
                    catch { }
                }
            }
        }

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

        /// <summary>Raises the alert for a flagged file. <paramref name="pid"/> is who wrote it (0 = an on-demand scan).</summary>
        public void Report(ScanResult r, int pid, string how)
        {
            if (pid != 0 && Seen("s:" + (r.Sha256 ?? r.Path), 600)) return;
            string name = System.IO.Path.GetFileName(r.Path);
            string who = null;
            if (pid > 4) { string pp = Procs.ImagePath(pid); who = (pp ?? "bilinmeyen program") + " (PID " + pid + ")"; }

            string detail = string.Join(Environment.NewLine, r.Reasons.Select(x => "• " + x)) + Environment.NewLine +
                "Puan: " + r.Score + "/100" + Environment.NewLine +
                "Dosya: " + r.Path + Environment.NewLine +
                (who != null ? "Bırakan: " + who + Environment.NewLine : "") +
                (r.Signed ? "Yayıncı: " + r.Publisher : "İmza: yok") + Environment.NewLine +
                "SHA-256: " + r.Sha256;

            Alert a = new Alert(r.Verdict == 2 ? Sev.Danger : Sev.Warn, "scan", name + (r.Verdict == 2 ? " zararlı görünüyor" : " şüpheli görünüyor"), detail);
            string path = r.Path, sha = r.Sha256;
            bool auto = pid != 0 && r.HardHit && Settings.Mode == "ask" && !Dry && !Settings.Paused;
            string id = auto ? Quarantine.Put(path, r.Summary()) : null;
            if (id != null)
            {
                a.Title = name + " karantinaya alındı";
                a.Actions.Add(new AlertAction("Geri yükle", () => { if (Quarantine.Restore(id, null)) { Store.Allow(sha, path); Scanner.ForgetCache(); } a.Resolved = true; }));
            }
            else
            {
                if (!Dry) a.Actions.Add(new AlertAction("Karantinaya al", () => { Quarantine.Put(path, r.Summary()); a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Güvenilir yap", () => { Store.Allow(sha, path); Scanner.ForgetCache(); a.Resolved = true; }));
            }
            Hub.Raise(a);
        }

        /// <summary>Scans one file or a whole folder tree. Returns how many files were looked at.</summary>
        public static int ScanPath(string path, Action<ScanResult> onHit, Func<bool> cancelled)
        {
            int count = 0;
            if (File.Exists(path))
            {
                ScanResult r = Scanner.ScanFile(path);
                if (r.Verdict > 0 && onHit != null) onHit(r);
                return 1;
            }
            if (!Directory.Exists(path)) return 0;
            object gate = new object();
            // leave one core to the rest of the machine
            ParallelOptions po = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(4, Environment.ProcessorCount - 1)) };
            try
            {
                Parallel.ForEach(Walk(path, cancelled), po, (f, state) =>
                {
                    if (cancelled != null && cancelled()) { state.Stop(); return; }
                    try
                    {
                        if (new FileInfo(f).Length > 300L * 1024 * 1024) return;
                        Interlocked.Increment(ref count);
                        ScanResult r = Scanner.ScanFile(f);
                        if (r.Verdict > 0 && onHit != null) lock (gate) onHit(r);
                    }
                    catch { }
                });
            }
            catch { }
            return count;
        }

        /// <summary>Every scannable file under a folder; junctions and symbolic links are not followed.</summary>
        static IEnumerable<string> Walk(string root, Func<bool> cancelled)
        {
            Stack<string> dirs = new Stack<string>();
            dirs.Push(root);
            while (dirs.Count > 0)
            {
                if (cancelled != null && cancelled()) yield break;
                string d = dirs.Pop();
                string[] files = null, subs = null;
                try { files = Directory.GetFiles(d); subs = Directory.GetDirectories(d); } catch { continue; }
                foreach (string s in subs)
                {
                    try { if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) == 0) dirs.Push(s); } catch { }
                }
                foreach (string f in files) if (Scanner.IsScannable(f)) yield return f;
            }
        }

        public void Dispose() { stop = true; }
    }

    /// <summary><c>Nobetci.exe --scan &lt;dosya|klasör&gt;</c>: prints a report, exit code 0 clean / 1 suspicious / 2 malicious.</summary>
    static class ScanCli
    {
        [DllImport("kernel32.dll")]
        static extern bool AttachConsole(int pid);

        public static int Run(string[] args)
        {
            int i = Array.IndexOf(args, "--scan");
            string target = i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
            StringBuilder report = new StringBuilder();
            int worst = 0;
            if (target == null || (!File.Exists(target) && !Directory.Exists(target)))
            {
                report.AppendLine("Kullanım: Nobetci.exe --scan <dosya ya da klasör>");
                worst = 3;
            }
            else
            {
                Drivers.UpdateIfStale();
                Stopwatch sw = Stopwatch.StartNew();
                int hits = 0;
                int n = ScanService.ScanPath(System.IO.Path.GetFullPath(target), r =>
                {
                    hits++;
                    if (r.Verdict > worst) worst = r.Verdict;
                    report.AppendLine("[" + r.VerdictText + " " + r.Score + "/100] " + r.Path);
                    foreach (string why in r.Reasons) report.AppendLine("    - " + why);
                    report.AppendLine("    SHA-256: " + r.Sha256);
                }, null);
                report.AppendLine();
                report.AppendLine(n + " dosya tarandı, " + hits + " tanesi işaretlendi (" + sw.Elapsed.TotalSeconds.ToString("0.0") + " sn). AMSI: " + (Amsi.Available ? "var" : "yok") + ", sürücü listesi: " + Drivers.HashCount + " özet.");
                report.AppendLine("Süre dağılımı (iş parçacıkları toplamı): " + Scanner.Timing() + ".");
            }
            string text = report.ToString();
            try { File.WriteAllText(Store.PathOf("scan-report.txt"), text, Encoding.UTF8); } catch { }
            try
            {
                if (AttachConsole(-1))
                {
                    using (StreamWriter w = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false))) { w.WriteLine(); w.Write(text); }
                }
            }
            catch { }
            return worst;
        }
    }
}
