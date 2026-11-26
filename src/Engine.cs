using System;

namespace Nobetci
{
    /// <summary>Starts and owns all the watchers. The tray app and the self-test both use it.</summary>
    public sealed class Engine : IDisposable
    {
        public readonly BehaviorGuard Behavior = new BehaviorGuard();
        public readonly AutorunWatch Autorun = new AutorunWatch();
        public readonly TamperGuard Tamper = new TamperGuard();
        public readonly SpyGuard Spy = new SpyGuard();
        public readonly RansomGuard Ransom = new RansomGuard();
        public readonly ScanService Scan = new ScanService();
        public EtwMonitor Etw;
        public bool EtwOk;
        public string EtwError;

        public void Start(bool dry)
        {
            Behavior.Dry = dry; Autorun.Dry = dry; Tamper.Dry = dry; Spy.Dry = dry; Ransom.Dry = dry; Scan.Dry = dry;
            Behavior.Start();
            Spy.Start();
            Ransom.Start();
            Scan.Start();

            Etw = new EtwMonitor();
            Etw.ProcessStarted += Behavior.OnProcess;
            Etw.RegistryWritten += Behavior.OnRegistry;
            Etw.FileChanged += Behavior.OnFile;
            Etw.FileChanged += Ransom.OnFile;
            Etw.FileChanged += Scan.OnFile;
            Etw.Spied += Spy.OnSpy;
            EtwOk = Etw.Start();
            EtwError = Etw.Error;
            if (!EtwOk)
                Hub.Raise(new Alert(Sev.Warn, "engine", "Gerçek zamanlı izleme açılamadı",
                    "Çekirdek olayları okunamıyor (" + EtwError + "). Programı yönetici olarak çalıştır. Otomatik başlatma ve hosts denetimi yine de çalışıyor."));

            Autorun.Start();
            Tamper.Start();
        }

        public void Dispose()
        {
            try { Autorun.Dispose(); } catch { }
            try { Tamper.Dispose(); } catch { }
            try { if (Etw != null) Etw.Dispose(); } catch { }
            try { Spy.Dispose(); } catch { }
            try { Ransom.Dispose(); } catch { }
            try { Scan.Dispose(); } catch { }
        }
    }
}
