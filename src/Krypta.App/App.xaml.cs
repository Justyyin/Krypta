using System.Security.Principal;
using System.Windows;
using Krypta.App.Services;

namespace Krypta.App;

public partial class App : Application
{
    private Mutex? _singleInstance;

    /// <summary>Set by tests that create the windows themselves.</summary>
    internal static bool SkipStartup { get; set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (SkipStartup) return;
        Hardening.ProtectProcess();
        var settings = AppSettings.Load();
        Appearance.Apply(settings.Theme, settings.Accent);
        Hardening.BlockScreenCapture = settings.BlockScreenCapture;
        Loc.Apply(settings.Language);

        string user = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        _singleInstance = new Mutex(true, "Krypta.SingleInstance." + user, out bool first);
        if (!first)
        {
            MessageBox.Show(Loc.T("App.AlreadyRunning"), "Krypta", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        MainWindow = new MainWindow(settings);
        MainWindow.Show();
    }
}
