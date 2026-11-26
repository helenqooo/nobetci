using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Nobetci
{
    internal static class Native
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_SUSPEND_RESUME = 0x0800;
        public const uint PROCESS_TERMINATE = 0x0001;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(IntPtr h);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        /// <summary>True when the file carries a valid embedded Authenticode signature (no network lookups).</summary>
        public static bool HasValidSignature(string path)
        {
            IntPtr pFile = IntPtr.Zero;
            try
            {
                WINTRUST_FILE_INFO fi = new WINTRUST_FILE_INFO();
                fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
                fi.pcwszFilePath = path;
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fi, pFile, false);

                WINTRUST_DATA d = new WINTRUST_DATA();
                d.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                d.dwUIChoice = 2;               // WTD_UI_NONE
                d.fdwRevocationChecks = 0;      // WTD_REVOKE_NONE
                d.dwUnionChoice = 1;            // WTD_CHOICE_FILE
                d.pFile = pFile;
                d.dwStateAction = 0;            // WTD_STATEACTION_IGNORE
                d.dwProvFlags = 0x1000 | 0x10;  // cache-only URL retrieval, no revocation check

                Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                return WinVerifyTrust(IntPtr.Zero, ref action, ref d) == 0;
            }
            catch { return false; }
            finally { if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile); }
        }
    }

    /// <summary>
    /// Windows signs most of its own files through security catalogs rather than inside the file:
    /// the file's hash is listed in a signed .cat file under System32\CatRoot.
    /// </summary>
    internal static class Catalog
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint cbHash, byte[] hash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint cbHash, uint flags, IntPtr prev);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catInfo, uint flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

        /// <summary>The installed catalog that lists this file, or null. The caller still has to verify the catalog's own signature.</summary>
        public static string Find(string path)
        {
            foreach (string alg in new[] { "SHA256", "SHA1" })
            {
                IntPtr admin;
                try { if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue; } catch { return null; }
                try
                {
                    byte[] hash = new byte[64];
                    uint cb = (uint)hash.Length;
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref cb, hash, 0)) continue;
                    }
                    IntPtr info = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, IntPtr.Zero);
                    if (info == IntPtr.Zero) continue;
                    try
                    {
                        CATALOG_INFO ci = new CATALOG_INFO();
                        ci.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                        if (CryptCATCatalogInfoFromContext(info, ref ci, 0) && !string.IsNullOrEmpty(ci.wszCatalogFile)) return ci.wszCatalogFile;
                    }
                    finally { CryptCATAdminReleaseCatalogContext(admin, info, 0); }
                }
                catch { }
                finally { CryptCATAdminReleaseContext(admin, 0); }
            }
            return null;
        }
    }

    internal class SigInfo
    {
        public bool Signed;
        /// <summary>Signed through a Windows security catalog, not inside the file.</summary>
        public bool Catalog;
        public string Publisher = "";
    }

    internal static class Sig
    {
        static readonly object gate = new object();
        static readonly System.Collections.Generic.Dictionary<string, SigInfo> cache =
            new System.Collections.Generic.Dictionary<string, SigInfo>(StringComparer.OrdinalIgnoreCase);

        public static SigInfo Check(string path) { return Check(path, true); }

        static SigInfo Check(string path, bool catalogs)
        {
            if (string.IsNullOrEmpty(path)) return new SigInfo();
            string key;
            try { key = path + "|" + File.GetLastWriteTimeUtc(path).Ticks; } catch { return new SigInfo(); }
            lock (gate) { SigInfo hit; if (cache.TryGetValue(key, out hit)) return hit; }
            SigInfo r = new SigInfo();
            r.Signed = Native.HasValidSignature(path);
            if (r.Signed)
            {
                try
                {
                    X509Certificate c = X509Certificate.CreateFromSignedFile(path);
                    X509Certificate2 c2 = new X509Certificate2(c);
                    // the organisation is what a person recognises ("Microsoft Corporation"); the CN can be a product name (".NET")
                    System.Text.RegularExpressions.Match o = System.Text.RegularExpressions.Regex.Match(c2.Subject, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
                    r.Publisher = o.Success ? o.Groups[1].Value.Trim('"') : c2.GetNameInfo(X509NameType.SimpleName, false);
                }
                catch { }
            }
            else if (catalogs)
            {
                string cat = Catalog.Find(path);
                if (cat != null)
                {
                    SigInfo c = Check(cat, false);
                    if (c.Signed) { r.Signed = true; r.Catalog = true; r.Publisher = c.Publisher; }
                }
            }
            lock (gate) { if (cache.Count > 4000) cache.Clear(); cache[key] = r; }
            return r;
        }
    }

    internal static class Procs
    {
        // programs that live for a few milliseconds are gone before their events arrive: remember what each pid was
        static readonly System.Collections.Generic.Dictionary<int, string> seen = new System.Collections.Generic.Dictionary<int, string>();

        public static void Started(int pid) { lock (seen) seen.Remove(pid); }

        static readonly System.Collections.Generic.Dictionary<string, string> origNames =
            new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The name the file was built with (version resource), lower-cased: it survives renaming.</summary>
        public static string OriginalName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            string key;
            try { key = path + "|" + File.GetLastWriteTimeUtc(path).Ticks; } catch { return ""; }
            lock (origNames) { string hit; if (origNames.TryGetValue(key, out hit)) return hit; }
            string n = "";
            try
            {
                n = (FileVersionInfo.GetVersionInfo(path).OriginalFilename ?? "").Trim().ToLowerInvariant();
                if (n.EndsWith(".mui")) n = n.Substring(0, n.Length - 4);
            }
            catch { }
            lock (origNames) { if (origNames.Count > 4000) origNames.Clear(); origNames[key] = n; }
            return n;
        }

        public static void Loaded(int pid, string image)
        {
            lock (seen)
            {
                if (seen.Count > 6000) seen.Clear();
                if (!seen.ContainsKey(pid)) seen[pid] = image;
            }
        }

        public static string ImagePath(int pid)
        {
            string p = LivePath(pid);
            if (p != null) return p;
            lock (seen) return seen.TryGetValue(pid, out p) ? p : null;
        }

        /// <summary>For a program that has just started: if it is already gone, give its image-load event a moment to arrive.</summary>
        public static string ImagePathWait(int pid, int ms)
        {
            string p = ImagePath(pid);
            for (int waited = 0; p == null && waited < ms; waited += 25)
            {
                System.Threading.Thread.Sleep(25);
                lock (seen) seen.TryGetValue(pid, out p);
            }
            return p;
        }

        static string LivePath(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return Native.QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { Native.CloseHandle(h); }
        }

        public static bool Suspend(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return Native.NtSuspendProcess(h) == 0; } finally { Native.CloseHandle(h); }
        }

        public static bool Resume(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return Native.NtResumeProcess(h) == 0; } finally { Native.CloseHandle(h); }
        }

        public static bool Kill(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_TERMINATE, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return Native.TerminateProcess(h, 1); } finally { Native.CloseHandle(h); }
        }

        public static string Sha256(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] h = sha.ComputeHash(fs);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in h) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }
    }
}
