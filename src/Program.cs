using System;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Nobetci
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Contains("--selftest")) return SelfTest.Run();
            if (args.Contains("--scan")) return ScanCli.Run(args);

            bool createdNew;
            using (Mutex mutex = new Mutex(true, @"Global\NobetciGuard", out createdNew))
            {
                if (!createdNew) return 0;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new TrayApp(args.Contains("--dry")));
            }
            return 0;
        }
    }
}
