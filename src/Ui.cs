using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Nobetci
{
    static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(18, 20, 24);
        public static readonly Color Panel = Color.FromArgb(28, 31, 37);
        public static readonly Color Text = Color.FromArgb(232, 234, 238);
        public static readonly Color Muted = Color.FromArgb(150, 156, 168);
        public static readonly Color Danger = Color.FromArgb(229, 72, 77);
        public static readonly Color Warn = Color.FromArgb(245, 165, 36);
        public static readonly Color Info = Color.FromArgb(70, 140, 255);
        public static Color For(Sev s) { return s == Sev.Danger ? Danger : s == Sev.Warn ? Warn : Info; }
        public static string Label(Sev s) { return s == Sev.Danger ? "Tehlike" : s == Sev.Warn ? "Uyarı" : "Bilgi"; }

        public static Icon ShieldIcon(Color c)
        {
            using (Bitmap bmp = new Bitmap(32, 32))
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using (GraphicsPath p = new GraphicsPath())
                {
                    p.AddPolygon(new[] { new Point(16, 2), new Point(28, 7), new Point(27, 18), new Point(16, 30), new Point(5, 18), new Point(4, 7) });
                    using (SolidBrush b = new SolidBrush(c)) g.FillPath(b, p);
                    using (Pen pen = new Pen(Color.White, 2.2f)) { g.DrawLine(pen, 10, 16, 15, 21); g.DrawLine(pen, 15, 21, 23, 11); }
                }
                return Icon.FromHandle(bmp.GetHicon());
            }
        }
    }

    /// <summary>A small always-on-top card in the corner. Never steals keyboard focus.</summary>
    sealed class Toast : Form
    {
        static readonly List<Toast> open = new List<Toast>();
        System.Windows.Forms.Timer life;

        protected override bool ShowWithoutActivation { get { return true; } }
        protected override CreateParams CreateParams
        {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= 0x80 | 0x08000000; return cp; }
        }

        public Toast(Alert a)
        {
            FormBorderStyle = FormBorderStyle.None; TopMost = true; ShowInTaskbar = false; StartPosition = FormStartPosition.Manual;
            BackColor = Theme.Panel; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f); Width = 440; AutoScaleMode = AutoScaleMode.None;

            Panel bar = new Panel { Dock = DockStyle.Left, Width = 6, BackColor = Theme.For(a.Severity) };
            FlowLayoutPanel body = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(14, 10, 12, 10), AutoSize = true };
            Label title = new Label { Text = a.Title, Font = new Font("Segoe UI Semibold", 10.5f), ForeColor = Theme.Text, AutoSize = true, MaximumSize = new Size(380, 0), Margin = new Padding(0, 0, 0, 4) };
            Label detail = new Label { Text = Clip(a.Detail), ForeColor = Theme.Muted, AutoSize = true, MaximumSize = new Size(400, 150), Margin = new Padding(0, 0, 0, 8) };
            body.Controls.Add(title); body.Controls.Add(detail);

            if (a.Actions.Count > 0)
            {
                FlowLayoutPanel row = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0) };
                foreach (AlertAction act in a.Actions)
                {
                    AlertAction x = act;
                    Button b = new Button { Text = x.Label, AutoSize = true, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(44, 48, 56), ForeColor = Theme.Text, Padding = new Padding(8, 2, 8, 2), Margin = new Padding(0, 0, 8, 0) };
                    b.FlatAppearance.BorderColor = Color.FromArgb(70, 76, 88);
                    b.Click += (s, e) => { ThreadPool.QueueUserWorkItem(_ => { try { x.Run(); } catch { } }); Close(); };
                    row.Controls.Add(b);
                }
                body.Controls.Add(row);
            }
            Label close = new Label { Text = "×", ForeColor = Theme.Muted, Font = new Font("Segoe UI", 13f), AutoSize = true, Cursor = Cursors.Hand, Location = new Point(Width - 24, 2) };
            close.Click += (s, e) => Close();
            Controls.Add(body); Controls.Add(bar); Controls.Add(close); close.BringToFront();

            body.PerformLayout();
            Height = Math.Max(70, body.PreferredSize.Height + 4);

            int secs = a.Pending ? 0 : a.Severity == Sev.Danger ? 45 : a.Severity == Sev.Warn ? 25 : 8;
            if (secs > 0)
            {
                life = new System.Windows.Forms.Timer { Interval = secs * 1000 };
                life.Tick += (s, e) => Close();
                life.Start();
            }
            Shown += (s, e) => Place(this);
            FormClosed += (s, e) => { open.Remove(this); Restack(); };
        }

        static string Clip(string s) { s = s ?? ""; return s.Length > 520 ? s.Substring(0, 520) + "…" : s; }

        static void Place(Toast t) { open.Add(t); Restack(); }

        static void Restack()
        {
            Rectangle wa = Screen.PrimaryScreen.WorkingArea;
            int y = wa.Bottom - 12;
            for (int i = open.Count - 1; i >= 0; i--)
            {
                Toast t = open[i];
                y -= t.Height;
                t.Location = new Point(wa.Right - t.Width - 12, y);
                y -= 8;
            }
        }
    }

    sealed class UiSink : IAlertSink
    {
        readonly Control marshal;
        public Action<Alert> Notified;
        public UiSink(Control c) { marshal = c; }

        public void Raise(Alert a)
        {
            if (marshal.IsDisposed) return;
            marshal.BeginInvoke((Action)(() =>
            {
                if (a.Severity >= Sev.Warn || a.Pending) { Toast t = new Toast(a); t.Show(); }
                if (Notified != null) Notified(a);
            }));
        }
    }

    sealed class MainForm : Form
    {
        readonly ListView list = new ListView();
        readonly TextBox detail = new TextBox();
        readonly FlowLayoutPanel actions = new FlowLayoutPanel();
        readonly CheckBox ask = new CheckBox();
        readonly CheckBox strict = new CheckBox();
        readonly Label status = new Label();
        int shown;
        readonly List<Alert> rows = new List<Alert>();

        public MainForm(Engine engine, bool dry)
        {
            Text = "Nöbetçi"; Width = 980; Height = 640; BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f);
            StartPosition = FormStartPosition.CenterScreen; Icon = Theme.ShieldIcon(Theme.Info);

            Panel top = new Panel { Dock = DockStyle.Top, Height = 74, BackColor = Theme.Panel, Padding = new Padding(16, 10, 16, 8) };
            Label name = new Label { Text = "Nöbetçi", Font = new Font("Segoe UI Semibold", 15f), AutoSize = true, Location = new Point(16, 8) };
            status.AutoSize = true; status.ForeColor = Theme.Muted; status.Location = new Point(18, 42);
            top.Controls.Add(name); top.Controls.Add(status);

            ask.Text = "Şüpheli programı durdurup sor"; ask.AutoSize = true; ask.Location = new Point(420, 14); ask.Checked = Settings.Mode == "ask";
            strict.Text = "İmzasız + kullanıcı klasörü = şüpheli"; strict.AutoSize = true; strict.Location = new Point(420, 40); strict.Checked = Settings.Strict;
            ask.CheckedChanged += (s, e) => { Settings.Mode = ask.Checked ? "ask" : "monitor"; Refresh2(engine, dry); };
            strict.CheckedChanged += (s, e) => Settings.Strict = strict.Checked;
            if (dry) { ask.Enabled = false; ask.Text += " (kuru çalışma: kapalı)"; }
            top.Controls.Add(ask); top.Controls.Add(strict);

            list.Dock = DockStyle.Fill; list.View = View.Details; list.FullRowSelect = true; list.BackColor = Theme.Bg; list.ForeColor = Theme.Text; list.BorderStyle = BorderStyle.None; list.HideSelection = false;
            list.Columns.Add("Zaman", 130); list.Columns.Add("Seviye", 70); list.Columns.Add("Tür", 80); list.Columns.Add("Olay", 640);
            list.SelectedIndexChanged += (s, e) => ShowSelected();

            Panel bottom = new Panel { Dock = DockStyle.Bottom, Height = 200, BackColor = Theme.Panel, Padding = new Padding(12) };
            detail.Multiline = true; detail.ReadOnly = true; detail.Dock = DockStyle.Fill; detail.BackColor = Theme.Panel; detail.ForeColor = Theme.Text; detail.BorderStyle = BorderStyle.None; detail.ScrollBars = ScrollBars.Vertical;
            actions.Dock = DockStyle.Bottom; actions.Height = 38; actions.FlowDirection = FlowDirection.LeftToRight;
            bottom.Controls.Add(detail); bottom.Controls.Add(actions);

            Controls.Add(list); Controls.Add(bottom); Controls.Add(top);

            System.Windows.Forms.Timer t = new System.Windows.Forms.Timer { Interval = 1200 };
            t.Tick += (s, e) => Pull(engine, dry);
            t.Start();
            FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); } };
            Pull(engine, dry);
        }

        void Refresh2(Engine engine, bool dry) { Pull(engine, dry); }

        void Pull(Engine engine, bool dry)
        {
            Alert[] all = Hub.Snapshot();
            if (all.Length > shown)
            {
                list.BeginUpdate();
                for (int i = shown; i < all.Length; i++)
                {
                    Alert a = all[i];
                    ListViewItem it = new ListViewItem(a.Time.ToString("dd.MM HH:mm:ss"));
                    it.SubItems.Add(Theme.Label(a.Severity)); it.SubItems.Add(a.Kind); it.SubItems.Add(a.Title);
                    it.ForeColor = a.Severity == Sev.Info ? Theme.Muted : Theme.For(a.Severity);
                    list.Items.Insert(0, it); rows.Insert(0, a);
                }
                shown = all.Length;
                list.EndUpdate();
            }
            int pending = all.Count(a => a.Pending);
            status.Text = (engine.EtwOk ? "Gerçek zamanlı izleme açık" : "Gerçek zamanlı izleme KAPALI (yönetici olarak çalıştır)") +
                "  ·  Mod: " + (dry ? "kuru çalışma" : Settings.Mode == "ask" ? "durdur ve sor" : "yalnız izle") +
                "  ·  " + all.Count(a => a.Severity == Sev.Danger) + " tehlike, " + all.Count(a => a.Severity == Sev.Warn) + " uyarı" +
                (pending > 0 ? "  ·  " + pending + " karar bekliyor" : "");
        }

        void ShowSelected()
        {
            actions.Controls.Clear();
            if (list.SelectedIndices.Count == 0) { detail.Text = ""; return; }
            Alert a = rows[list.SelectedIndices[0]];
            detail.Text = a.Title + Environment.NewLine + Environment.NewLine + a.Detail;
            if (a.Resolved) { detail.Text += Environment.NewLine + Environment.NewLine + "(Karar verildi)"; return; }
            foreach (AlertAction act in a.Actions)
            {
                AlertAction x = act;
                Button b = new Button { Text = x.Label, AutoSize = true, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(44, 48, 56), ForeColor = Theme.Text, Margin = new Padding(0, 0, 8, 0) };
                b.FlatAppearance.BorderColor = Color.FromArgb(70, 76, 88);
                b.Click += (s, e) => { ThreadPool.QueueUserWorkItem(_ => { try { x.Run(); } catch { } }); b.Enabled = false; };
                actions.Controls.Add(b);
            }
        }
    }

    sealed class TrayApp : ApplicationContext
    {
        readonly NotifyIcon icon = new NotifyIcon();
        readonly Engine engine = new Engine();
        readonly MainForm main;
        readonly Control marshal = new Control();
        readonly bool dry;

        public TrayApp(bool dry)
        {
            this.dry = dry;
            marshal.CreateControl();
            Hub.Sink = new UiSink(marshal);
            engine.Start(dry);
            Application.ApplicationExit += (s, e) => engine.Dispose();
            AppDomain.CurrentDomain.ProcessExit += (s, e) => engine.Dispose();
            main = new MainForm(engine, dry);

            icon.Icon = Theme.ShieldIcon(Theme.Info); icon.Text = "Nöbetçi"; icon.Visible = true;
            ContextMenuStrip m = new ContextMenuStrip();
            m.Items.Add("Olayları göster", null, (s, e) => ShowMain());
            m.Items.Add("Dosya tara…", null, (s, e) => { using (OpenFileDialog d = new OpenFileDialog { Title = "Taranacak dosyayı seç" }) if (d.ShowDialog() == DialogResult.OK) ScanNow(d.FileName); });
            m.Items.Add("Klasör tara…", null, (s, e) => { using (FolderBrowserDialog d = new FolderBrowserDialog { Description = "Taranacak klasörü seç" }) if (d.ShowDialog() == DialogResult.OK) ScanNow(d.SelectedPath); });
            m.Items.Add("10 dakika duraklat", null, (s, e) => { Settings.Paused = true; System.Threading.Timer t = null; t = new System.Threading.Timer(_ => { Settings.Paused = false; t.Dispose(); }, null, 10 * 60 * 1000, Timeout.Infinite); });
            m.Items.Add("Çıkış", null, (s, e) => { icon.Visible = false; engine.Dispose(); Application.Exit(); });
            icon.ContextMenuStrip = m;
            icon.DoubleClick += (s, e) => ShowMain();
            if (!Environment.GetCommandLineArgs().Contains("--hidden")) ShowMain();
        }

        void ScanNow(string path)
        {
            ShowMain();
            ThreadPool.QueueUserWorkItem(_ =>
            {
                int hits = 0;
                int n = ScanService.ScanPath(path, r => { hits++; engine.Scan.Report(r, 0, "tarandı"); }, null);
                Hub.Raise(new Alert(Sev.Info, "scan", "Tarama bitti: " + n + " dosya, " + hits + " tanesi işaretlendi", path));
            });
        }

        void ShowMain() { main.Show(); main.WindowState = FormWindowState.Normal; main.Activate(); }
    }
}
