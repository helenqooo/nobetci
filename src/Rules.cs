using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Nobetci
{
    public class Finding
    {
        public Sev Severity;
        public string Code;
        public string Text;
        public Finding(Sev s, string code, string text) { Severity = s; Code = code; Text = text; }
    }

    /// <summary>What a command line or a file location says about intent. Pure functions, easy to test.</summary>
    public static class Rules
    {
        class Rule
        {
            public Regex Rx; public Sev Sev; public string Code; public string Text;
            public Rule(string rx, Sev sev, string code, string text)
            {
                Rx = new Regex(rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
                Sev = sev; Code = code; Text = text;
            }
        }

        static readonly Rule[] CmdRules = new Rule[]
        {
            new Rule(@"netsh(\.exe)?\b.*advfirewall.*state\s+off|netsh(\.exe)?\b.*firewall.*(disable|state\s+off)", Sev.Danger, "fw-off", "Güvenlik duvarını kapatmaya çalışıyor"),
            new Rule(@"Set-NetFirewallProfile.*-Enabled\s+(False|0)", Sev.Danger, "fw-off", "Güvenlik duvarını kapatmaya çalışıyor"),
            new Rule(@"Set-MpPreference\b.*(Disable\w+\s+\$?(true|1)|Exclusion(Path|Extension|Process))", Sev.Danger, "av-tamper", "Windows Defender ayarını değiştiriyor"),
            new Rule(@"Add-MpPreference\b.*Exclusion", Sev.Danger, "av-tamper", "Windows Defender'a dışlama ekliyor"),
            new Rule(@"sc(\.exe)?\s+(stop|config|delete)\s+(WinDefend|Sense|wscsvc|MpsSvc|SecurityHealthService)", Sev.Danger, "av-tamper", "Güvenlik servisini durdurmaya çalışıyor"),
            new Rule(@"DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection", Sev.Danger, "av-tamper", "Defender korumasını kapatan ayar yazıyor"),
            new Rule(@"/protection\s+off", Sev.Danger, "av-tamper", "Koruma yazılımını kapatma komutu çalıştırıyor"),
            new Rule(@"/op:uninstall_app", Sev.Danger, "av-tamper", "Yüklü bir uygulamayı kaldırma komutu çalıştırıyor"),
            new Rule(@"(cacls|icacls|takeown|attrib)(\.exe)?\b.*\\drivers\\etc\\hosts", Sev.Danger, "hosts", "hosts dosyasının izinlerini değiştiriyor"),
            new Rule(@"(>>?|\b(Add-Content|Set-Content|Out-File|copy|move|del|erase)\b).*\\drivers\\etc\\hosts", Sev.Danger, "hosts", "hosts dosyasını değiştiriyor"),
            new Rule(@"\bsc(\.exe)?\s+create\b.*(type=\s*(kernel|filesys)|\.sys\b)", Sev.Danger, "driver", "Sürücü servisi kuruyor"),
            new Rule(@"\bsc(\.exe)?\s+create\b", Sev.Warn, "service", "Yeni bir Windows servisi oluşturuyor"),
            new Rule(@"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no", Sev.Danger, "ransom", "Yedek ve kurtarma noktalarını siliyor"),
            new Rule(@"wevtutil(\.exe)?\s+(cl|clear-log)", Sev.Danger, "log-clear", "Olay günlüklerini siliyor"),
            new Rule(@"powershell(\.exe)?\b.*\s-(enc|e|ec|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", Sev.Warn, "ps-enc", "Şifreli PowerShell komutu çalıştırıyor"),
            new Rule(@"FromBase64String.*(iex|Invoke-Expression)|(iex|Invoke-Expression).*(DownloadString|FromBase64String)", Sev.Warn, "ps-dl", "PowerShell ile indirip çalıştırıyor"),
            new Rule(@"certutil(\.exe)?\b.*-urlcache|bitsadmin(\.exe)?\b.*/transfer|mshta(\.exe)?\s+https?:|regsvr32(\.exe)?\b.*/i:https?:", Sev.Warn, "lolbin-dl", "Sistem aracıyla internetten dosya çekiyor"),
            new Rule(@"reg(\.exe)?\s+add\b.*\\CurrentVersion\\(Run|RunOnce)\b", Sev.Warn, "autorun-cmd", "Başlangıç kaydı ekliyor"),
            new Rule(@"reg(\.exe)?\s+add\b.*Image File Execution Options", Sev.Danger, "ifeo", "Bir programın yerine başkasını çalıştıracak kayıt yazıyor"),
            new Rule(@"schtasks(\.exe)?\s+/create\b", Sev.Warn, "task-cmd", "Zamanlanmış görev oluşturuyor"),
        };

        public static List<Finding> CheckCommandLine(string cmd)
        {
            List<Finding> r = new List<Finding>();
            if (string.IsNullOrEmpty(cmd)) return r;
            HashSet<string> seen = new HashSet<string>();
            foreach (Rule x in CmdRules)
                if (x.Rx.IsMatch(cmd) && seen.Add(x.Code))
                    r.Add(new Finding(x.Sev, x.Code, x.Text));
            return r;
        }

        static readonly string[] UserWritable =
        {
            @"\appdata\local\temp\", @"\appdata\roaming\", @"\appdata\local\", @"\downloads\", @"\desktop\",
            @"\users\public\", @"\windows\temp\", @"\programdata\", @"\$recycle.bin\", @"\temp\"
        };

        /// <summary>Folders any user-level program can write to, where droppers like to live.</summary>
        public static bool IsUserWritable(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToLowerInvariant();
            foreach (string s in UserWritable) if (p.Contains(s)) return true;
            return false;
        }

        /// <summary>Windows and Program Files are admin-only, so a program living there is trusted by location.</summary>
        public static bool IsSystemLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToLowerInvariant();
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant() + "\\";
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant() + "\\";
            string pfx = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant() + "\\";
            return p.StartsWith(win) || p.StartsWith(pf) || p.StartsWith(pfx);
        }
    }
}
