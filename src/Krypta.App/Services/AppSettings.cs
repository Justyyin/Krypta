using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace Krypta.App.Services;

/// <summary>Non-secret preferences, stored as plain JSON in %APPDATA%\Krypta.</summary>
internal sealed class AppSettings
{
    /// <summary>"system", "de" or "en".</summary>
    public string Language { get; set; } = "system";
    public string VaultPath { get; set; } = "";
    public int AutoLockMinutes { get; set; } = 5;
    public int ClipboardClearSeconds { get; set; } = 20;
    public bool BlockScreenCapture { get; set; } = true;
    /// <summary>"system", "light" or "dark".</summary>
    public string Theme { get; set; } = "system";
    public string Accent { get; set; } = "system";
    public bool LockOnMinimize { get; set; }
    public bool CloseToTray { get; set; }
    /// <summary>Weekly automatic leak check. Off by default because it contacts Have I Been Pwned.</summary>
    public bool LeakMonitor { get; set; }
    /// <summary>Load website icons from the websites themselves. Off by default.</summary>
    public bool Favicons { get; set; }
    /// <summary>Vault files opened before, most recent first.</summary>
    public List<string> RecentVaults { get; set; } = [];

    public void RememberVault(string path)
    {
        RecentVaults.RemoveAll(known => string.Equals(known, path, StringComparison.OrdinalIgnoreCase));
        RecentVaults.Insert(0, path);
        if (RecentVaults.Count > 8) RecentVaults.RemoveRange(8, RecentVaults.Count - 8);
        VaultPath = path;
    }

    public static string DataDirectory =>
        Environment.GetEnvironmentVariable("KRYPTA_DATA_DIR") is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Krypta");

    private static string FilePath => Path.Combine(DataDirectory, "settings.json");

    public string EffectiveVaultPath =>
        string.IsNullOrWhiteSpace(VaultPath) ? Path.Combine(DataDirectory, "vault.krypta") : VaultPath;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>Switches the user interface between German and English at runtime.</summary>
internal static class Loc
{
    private static ResourceDictionary? _current;

    public static string Language { get; private set; } = "en";

    public static void Apply(string setting)
    {
        Language = setting switch
        {
            "de" or "en" => setting,
            _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "de" ? "de" : "en",
        };
        var dictionary = new ResourceDictionary
        {
            Source = new Uri($"/Krypta;component/Resources/Strings.{Language}.xaml", UriKind.Relative),
        };
        var merged = Application.Current.Resources.MergedDictionaries;
        if (_current is not null) merged.Remove(_current);
        merged.Add(dictionary);
        _current = dictionary;
    }

    public static string T(string key) => Application.Current.TryFindResource(key) as string ?? key;

    public static string F(string key, params object[] args) => string.Format(T(key), args);
}
