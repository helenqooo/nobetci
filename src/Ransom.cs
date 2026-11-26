using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace Nobetci
{
    /// <summary>
    /// Ransomware behaviour. Three independent signals, all from kernel file events:
    ///  - a program rewrites many documents and what it leaves behind no longer looks like the file type (encrypted),
    ///  - a program renames / re-extensions documents in bulk,
    ///  - anything touches a decoy file nobody has a reason to touch.
    /// </summary>
    public sealed class RansomGuard : IDisposable
    {
        static readonly HashSet<string> DocExt = new HashSet<string>(StringComparer.Ordinal)
        {
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "jpg", "jpeg", "png", "gif", "bmp", "psd",
            "mp3", "mp4", "mov", "avi", "zip", "rar", "7z", "sql", "db", "mdb", "csv", "json", "xml", "key", "pem", "kdbx"
        };
        // a second extension that is ordinary housekeeping, not "report.docx.locked"
        static readonly HashSet<string> BenignTail = new HashSet<string>(StringComparer.Ordinal)
        {
            "tmp", "temp", "bak", "old", "orig", "part", "partial", "crdownload", "download", "lnk", "log", "sig", "asc", "md5", "sha1", "sha256",
            "gz", "bz2", "xz", "zst", "lz4", "br", "meta", "import", "map", "swp", "lock", "new", "url", "exe", "dll"
        };
        static readonly HashSet<string> TextExt = new HashSet<string>(StringComparer.Ordinal) { "txt", "csv", "json", "xml", "sql", "rtf", "pem", "key" };
        static readonly HashSet<string> Critical = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "csrss.exe", "lsass.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "svchost.exe", "system" };

        const int WindowSeconds = 15;
        const int RenameLimit = 20, DeleteLimit = 40, AppendLimit = 10, WriteCheckFirst = 12;
        const string CanaryName = "!0_nobetci_tuzak_dosya_silme.docx";

        class Burst
        {
            public DateTime Start = DateTime.UtcNow;
            public readonly HashSet<string> Renamed = new HashSet<string>(), Deleted = new HashSet<string>(), Written = new HashSet<string>(), Appended = new HashSet<string>();
            public int WriteCheckAt = WriteCheckFirst;
            public bool RenameDone, DeleteDone, AppendDone, WriteDone;
        }

        readonly Dictionary<int, Burst> bursts = new Dictionary<int, Burst>();
        readonly BlockingCollection<Action> work = new BlockingCollection<Action>(500);
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        readonly int self = Process.GetCurrentProcess().Id;
        HashSet<string> canaries = new HashSet<string>();
        readonly List<string> planted = new List<string>();
        Thread worker;

        public bool Dry;
        /// <summary>Self-test only: lets the test process play the ransomware (never applies to the decoy files).</summary>
        public bool IncludeSelf;
        /// <summary>Where decoy files go. Null = the user's Documents, Desktop and Pictures (skipped in a dry run).</summary>
        public string[] CanaryDirs;
        /// <summary>Path fragments (lower case) whose churn is normal and is not counted.</summary>
        public string[] ExcludeDirs =
        {
            @"\appdata\", @"\windows\", @"\program files", @"\programdata\", @"\$recycle.bin\", @"\node_modules\", @"\.git\", @"\.nuget\",
            @"\site-packages\", @"\__pycache__\", @"\.cache\", @"\.vscode\", @"\obj\", @"\bin\debug\", @"\bin\release\"
        };

        public void Start()
        {
            worker = new Thread(() =>
            {
                foreach (Action a in work.GetConsumingEnumerable())
                {
                    try { a(); } catch { }
                }
            });
            worker.IsBackground = true;
            worker.Name = "ransom";
            worker.Start();
            if (CanaryDirs != null || (!Dry && Store.Get("canary", "1") == "1")) Plant();
        }

        // ---------------------------------------------------------------- decoys

        static byte[] CanaryBytes()
        {
            // starts like a real .docx (zip) so type-sniffing malware takes it, and is big enough to be worth encrypting
            StringBuilder sb = new StringBuilder("PK\u0003\u0004 Nobetci tuzak dosyasi. Bu dosyaya dokunan program fidye yazilimi sayilir; silmeyin.\r\n");
            for (int i = 0; i < 60; i++) sb.Append("Bu belge Nobetci tarafindan izleniyor. Satir ").Append(i).Append("\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        void Plant()
        {
            string[] dirs = CanaryDirs ?? new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
            };
            HashSet<string> set = new HashSet<string>();
            foreach (string d in dirs.Where(x => !string.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (!Directory.Exists(d)) continue;
                    string f = Path.Combine(d, CanaryName);
                    WriteCanary(f);
                    set.Add(Path.GetFullPath(f).ToLowerInvariant());
                    lock (planted) planted.Add(f);
                }
                catch { }
            }
            canaries = set;
        }

        static void WriteCanary(string f)
        {
            byte[] want = CanaryBytes();
            try
            {
                if (File.Exists(f))
                {
                    if (File.ReadAllBytes(f).SequenceEqual(want)) return;
                    File.SetAttributes(f, FileAttributes.Normal);
                }
            }
            catch { }
            File.WriteAllBytes(f, want);
            File.SetAttributes(f, FileAttributes.Hidden | FileAttributes.System);
        }

        public string[] CanaryFiles() { lock (planted) return planted.ToArray(); }

        // ---------------------------------------------------------------- event fast path (runs on the ETW thread for every file event)

        public void OnFile(FileEvent e)
        {
            if (e.Op == "create" || e.Pid <= 4) return;
            string p = e.Path;
            if (string.IsNullOrEmpty(p)) return;

            int slash = p.LastIndexOf('\\');
            int dot = p.LastIndexOf('.');
            if (dot <= slash || dot == p.Length - 1) return;
            string ext = p.Substring(dot + 1).ToLowerInvariant();
            bool appended = false;
            if (!DocExt.Contains(ext))
            {
                int dot2 = dot > 0 ? p.LastIndexOf('.', dot - 1) : -1;
                if (dot2 <= slash || ext.Length > 12 || BenignTail.Contains(ext)) return;
                if (!DocExt.Contains(p.Substring(dot2 + 1, dot - dot2 - 1).ToLowerInvariant())) return;
                appended = true;
            }

            string lp = p.ToLowerInvariant();
            if (!appended && canaries.Count > 0 && canaries.Contains(lp))
            {
                if (e.Pid == self) return;
                int cp = e.Pid; string op = e.Op;
                work.TryAdd(() => CanaryTouched(cp, p, op));
                return;
            }
            if (e.Pid == self && !IncludeSelf) return;
            foreach (string x in ExcludeDirs) if (lp.Contains(x)) return;

            int pid = e.Pid;
            Action todo = null;
            lock (bursts)
            {
                Burst b;
                DateTime now = DateTime.UtcNow;
                if (!bursts.TryGetValue(pid, out b) || (now - b.Start).TotalSeconds > WindowSeconds)
                {
                    if (bursts.Count > 400) bursts.Clear();
                    bursts[pid] = b = new Burst();
                }
                if (e.Op == "rename" && !appended)
                {
                    b.Renamed.Add(lp);
                    if (b.Renamed.Count >= RenameLimit && !b.RenameDone) { b.RenameDone = true; string[] s = b.Renamed.Take(6).ToArray(); int n = b.Renamed.Count; todo = () => Report(pid, "rename", n, s, false); }
                }
                else if (e.Op == "delete" && !appended)
                {
                    b.Deleted.Add(lp);
                    if (b.Deleted.Count >= DeleteLimit && !b.DeleteDone) { b.DeleteDone = true; string[] s = b.Deleted.Take(6).ToArray(); int n = b.Deleted.Count; todo = () => Report(pid, "delete", n, s, false); }
                }
                else if (e.Op == "write" && appended)
                {
                    b.Appended.Add(lp);
                    if (b.Appended.Count >= AppendLimit && !b.AppendDone) { b.AppendDone = true; string[] s = b.Appended.Take(6).ToArray(); int n = b.Appended.Count; todo = () => Report(pid, "append", n, s, false); }
                }
                else if (e.Op == "write")
                {
                    b.Written.Add(lp);
                    if (b.Written.Count >= b.WriteCheckAt && !b.WriteDone)
                    {
                        b.WriteCheckAt *= 2;
                        string[] all = b.Written.ToArray();
                        Burst owner = b;
                        todo = () => CheckContents(pid, all, owner);
                    }
                }
            }
            if (todo != null) work.TryAdd(todo);
        }

        // ---------------------------------------------------------------- content check

        /// <summary>Shannon entropy in bits per byte: text is 4–5, compressed or encrypted data is close to 8.</summary>
        public static double Entropy(byte[] buf, int len)
        {
            if (len <= 0) return 0;
            int[] c = new int[256];
            for (int i = 0; i < len; i++) c[buf[i]]++;
            double h = 0;
            for (int i = 0; i < 256; i++)
            {
                if (c[i] == 0) continue;
                double p = (double)c[i] / len;
                h -= p * Math.Log(p, 2);
            }
            return h;
        }

        static bool Starts(byte[] b, int len, int at, params byte[] sig)
        {
            if (len < at + sig.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (b[at + i] != sig[i]) return false;
            return true;
        }

        /// <summary>Does the header still match the extension? null = a type we have no signature for.</summary>
        static bool? HeaderMatches(string ext, byte[] b, int n)
        {
            switch (ext)
            {
                case "docx": case "xlsx": case "pptx": case "zip": case "odt": case "ods": return Starts(b, n, 0, 0x50, 0x4B);
                case "doc": case "xls": case "ppt": return Starts(b, n, 0, 0xD0, 0xCF, 0x11, 0xE0) || Starts(b, n, 0, 0x50, 0x4B);
                case "pdf": return Starts(b, n, 0, 0x25, 0x50, 0x44, 0x46);
                case "jpg": case "jpeg": return Starts(b, n, 0, 0xFF, 0xD8, 0xFF);
                case "png": return Starts(b, n, 0, 0x89, 0x50, 0x4E, 0x47);
                case "gif": return Starts(b, n, 0, 0x47, 0x49, 0x46, 0x38);
                case "bmp": return Starts(b, n, 0, 0x42, 0x4D);
                case "psd": return Starts(b, n, 0, 0x38, 0x42, 0x50, 0x53);
                case "rar": return Starts(b, n, 0, 0x52, 0x61, 0x72, 0x21);
                case "7z": return Starts(b, n, 0, 0x37, 0x7A, 0xBC, 0xAF);
                case "mp3": return Starts(b, n, 0, 0x49, 0x44, 0x33) || (n > 1 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0);
                case "mp4": case "mov": return Starts(b, n, 4, 0x66, 0x74, 0x79, 0x70) || Starts(b, n, 4, 0x6D, 0x6F, 0x6F, 0x76) || Starts(b, n, 4, 0x6D, 0x64, 0x61, 0x74) || Starts(b, n, 4, 0x77, 0x69, 0x64, 0x65) || Starts(b, n, 4, 0x66, 0x72, 0x65, 0x65);
                case "avi": return Starts(b, n, 0, 0x52, 0x49, 0x46, 0x46);
                case "db": return Starts(b, n, 0, 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65) ? true : (bool?)null;
                case "mdb": return Starts(b, n, 4, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64);
                case "kdbx": return Starts(b, n, 0, 0x03, 0xD9, 0xA2, 0x9A);
            }
            return null;
        }

        /// <summary>true = no longer looks like its type and is random-looking; false = fine; null = cannot tell.</summary>
        public static bool? LooksEncrypted(string ext, byte[] b, int n)
        {
            if (n < 512) return null;
            // a small sample of random bytes cannot reach 8 bits, so the bar moves with the sample size
            double bar = n >= 2048 ? 7.6 : 7.3;
            double h = Entropy(b, n);
            if (TextExt.Contains(ext)) return h > bar;
            bool? ok = HeaderMatches(ext, b, n);
            if (ok == null) return null;
            return !ok.Value && h > bar;
        }

        static bool? LooksEncrypted(string path)
        {
            try
            {
                string ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
                byte[] buf = new byte[4096];
                int n;
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    n = fs.Read(buf, 0, buf.Length);
                return LooksEncrypted(ext, buf, n);
            }
            catch { return null; }
        }

        void CheckContents(int pid, string[] files, Burst owner)
        {
            // files may still be mid-write when the count trips
            Thread.Sleep(300);
            int step = Math.Max(1, files.Length / 12), seen = 0, bad = 0;
            List<string> hits = new List<string>();
            for (int i = 0; i < files.Length && seen < 12; i += step)
            {
                bool? enc = LooksEncrypted(files[i]);
                if (enc == null) continue;
                seen++;
                if (enc.Value) { bad++; hits.Add(files[i]); }
            }
            if (seen < 4 || bad * 10 < seen * 6) return;
            owner.WriteDone = true;
            Report(pid, "encrypt", files.Length, hits.Take(6).ToArray(), true);
        }

        // ---------------------------------------------------------------- alerts

        bool Seen(string key, int seconds)
        {
            lock (recent)
            {
                DateTime t;
                DateTime now = DateTime.UtcNow;
                if (recent.TryGetValue(key, out t) && (now - t).TotalSeconds < seconds) return true;
                if (recent.Count > 1000) recent.Clear();
                recent[key] = now;
                return false;
            }
        }

        void Report(int pid, string kind, int count, string[] samples, bool proof)
        {
            string path = Procs.ImagePath(pid);
            string name = path == null ? "PID " + pid : Path.GetFileName(path);
            bool trusted = path != null && Trust.IsTrusted(path);
            bool host = Trust.IsScriptHost(path);

            Sev sev; string what, why;
            if (kind == "encrypt")
            {
                sev = Sev.Danger; what = "belgeleri şifreliyor olabilir";
                why = count + " belgeyi " + WindowSeconds + " saniye içinde yeniden yazdı; baktığımız örneklerin içeriği artık dosya türüne uymuyor ve rastgele veri gibi (şifrelenmiş).";
            }
            else if (kind == "delete")
            {
                // bulk deletes are what cleaners and uninstallers do too
                if (trusted) return;
                sev = Sev.Warn; what = "belgeleri toplu halde siliyor";
                why = count + " belgeyi " + WindowSeconds + " saniye içinde sildi.";
            }
            else
            {
                if (trusted) return;
                sev = host ? Sev.Warn : Sev.Danger;
                what = kind == "rename" ? "belgeleri toplu halde yeniden adlandırıyor" : "belgelere yeni uzantı ekliyor";
                why = kind == "rename"
                    ? count + " belgeyi " + WindowSeconds + " saniye içinde yeniden adlandırdı (fidye yazılımları şifreledikleri dosyanın adını böyle değiştirir)."
                    : count + " belgenin yanına, belge uzantısının arkasına yeni uzantı eklenmiş kopyalar yazdı (ör. rapor.docx.locked).";
            }
            if (Seen(kind + ":" + (path ?? pid.ToString()), 120)) return;

            SigInfo sig = path == null ? new SigInfo() : Sig.Check(path);
            string detail = why + Environment.NewLine +
                "Program: " + (path ?? "bilinmiyor (kapanmış)") + " (PID " + pid + ")" + Environment.NewLine +
                (sig.Signed ? "Yayıncı: " + sig.Publisher : host ? "Bir betik çalıştırıcısı: asıl işi yapan, çalıştırdığı betik." : "İmza: yok") + Environment.NewLine +
                "Örnek dosyalar: " + string.Join(", ", samples.Select(s => Path.GetFileName(s)));
            Raise(new Alert(sev, "ransom", name + " " + what, detail), pid, path, name, what);
        }

        void CanaryTouched(int pid, string file, string op)
        {
            string path = Procs.ImagePath(pid);
            string name = path == null ? "PID " + pid : Path.GetFileName(path);
            // someone tidying up in Explorer with hidden files shown is not an attack
            bool explorer = name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            if (!Seen("canary:" + (path ?? pid.ToString()), 60))
            {
                string did = op == "delete" ? "sildi" : op == "rename" ? "yeniden adlandırdı" : "değiştirdi";
                string detail = "Tuzak dosyayı " + did + ". Bu dosyayı hiçbir programın açıp değiştirmesi için sebep yok; sırayla her belgeyi şifreleyen yazılımlar buna takılır." + Environment.NewLine +
                    "Program: " + (path ?? "bilinmiyor (kapanmış)") + " (PID " + pid + ")" + Environment.NewLine +
                    "Dosya: " + file;
                Raise(new Alert(explorer ? Sev.Warn : Sev.Danger, "ransom", name + " tuzak dosyaya dokundu", detail), pid, path, name, "tuzak dosyaya dokundu");
            }
            // put the decoy back so it keeps working
            Thread.Sleep(700);
            try { WriteCanary(file); } catch { }
        }

        void Raise(Alert a, int pid, string path, string name, string what)
        {
            bool ask = Settings.Mode == "ask" && !Dry && !Settings.Paused && a.Severity == Sev.Danger && path != null && !Critical.Contains(name);
            if (ask && Procs.Suspend(pid))
            {
                a.Pending = true;
                a.Title = name + " durduruldu: " + what;
                a.Actions.Add(new AlertAction("İzin ver", () => { Procs.Resume(pid); Store.Allow(Procs.Sha256(path), path); Trust.Forget(path); a.Pending = false; a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Engelle", () => { Procs.Kill(pid); a.Pending = false; a.Resolved = true; }));
            }
            else if (path != null)
            {
                if (!Dry && !Critical.Contains(name)) a.Actions.Add(new AlertAction("Sonlandır", () => { Procs.Kill(pid); a.Resolved = true; }));
                a.Actions.Add(new AlertAction("Güvenilir yap", () => { Store.Allow(Procs.Sha256(path), path); Trust.Forget(path); a.Resolved = true; }));
            }
            Hub.Raise(a);
        }

        public void Dispose()
        {
            try { work.CompleteAdding(); } catch { }
            canaries = new HashSet<string>();
            foreach (string f in CanaryFiles())
            {
                try { if (File.Exists(f)) { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); } } catch { }
            }
        }
    }
}
