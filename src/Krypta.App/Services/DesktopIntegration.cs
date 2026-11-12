using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace Krypta.App.Services;

/// <summary>Icon in the Windows notification area with a click and a right-click action.</summary>
internal sealed class TrayIcon : IDisposable
{
    public const int CallbackMessage = 0x8000 + 1; // WM_APP + 1
    private const int NimAdd = 0, NimDelete = 2;
    private const int NifMessage = 1, NifIcon = 2, NifTip = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public int Size;
        public IntPtr Window;
        public int Id;
        public int Flags;
        public int Callback;
        public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public int State;
        public int StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public int Version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public int InfoFlags;
        public Guid Item;
        public IntPtr BalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int message, ref NotifyIconData data);

    private NotifyIconData _data;
    private readonly System.Drawing.Icon? _icon;
    private bool _added;

    public TrayIcon(IntPtr window, string tip)
    {
        _icon = Environment.ProcessPath is { } path ? System.Drawing.Icon.ExtractAssociatedIcon(path) : null;
        _data = new NotifyIconData
        {
            Size = Marshal.SizeOf<NotifyIconData>(),
            Window = window,
            Id = 1,
            Flags = NifMessage | NifIcon | NifTip,
            Callback = CallbackMessage,
            Icon = _icon?.Handle ?? IntPtr.Zero,
            Tip = tip,
            Info = "",
            InfoTitle = "",
        };
        _added = Shell_NotifyIcon(NimAdd, ref _data);
    }

    public void Dispose()
    {
        if (_added) Shell_NotifyIcon(NimDelete, ref _data);
        _added = false;
        _icon?.Dispose();
    }
}

/// <summary>System-wide keyboard shortcuts.</summary>
internal static class GlobalHotkeys
{
    public const int Message = 0x0312; // WM_HOTKEY
    public const int QuickSearch = 1, PanicLock = 2;
    private const uint ModAlt = 0x1, ModControl = 0x2, ModNoRepeat = 0x4000;

    [DllImport("user32.dll")] private static extern bool RegisterHotKey(IntPtr window, int id, uint modifiers, uint key);
    [DllImport("user32.dll")] private static extern bool UnregisterHotKey(IntPtr window, int id);

    /// <summary>Ctrl+Alt+K opens the quick search, Ctrl+Alt+L locks. A shortcut another program owns is skipped.</summary>
    public static void Register(IntPtr window)
    {
        RegisterHotKey(window, QuickSearch, ModControl | ModAlt | ModNoRepeat, 0x4B);
        RegisterHotKey(window, PanicLock, ModControl | ModAlt | ModNoRepeat, 0x4C);
    }

    public static void Unregister(IntPtr window)
    {
        UnregisterHotKey(window, QuickSearch);
        UnregisterHotKey(window, PanicLock);
    }
}

/// <summary>Types text into the window that has the focus, so a secret never touches the clipboard.</summary>
internal static class AutoType
{
    private const uint InputKeyboard = 1, KeyUp = 0x2, Unicode = 0x4;
    private const ushort VkTab = 0x09;

    [StructLayout(LayoutKind.Sequential)]
    private struct MouseInput { public int X, Y; public uint Data, Flags, Time; public IntPtr Extra; }

    [StructLayout(LayoutKind.Sequential)]
    private struct KeyboardInput { public ushort Key, Scan; public uint Flags, Time; public IntPtr Extra; }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MouseInput Mouse;
        [FieldOffset(0)] public KeyboardInput Keyboard;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Input { public uint Type; public InputUnion Data; }

    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint count, Input[] inputs, int size);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    /// <summary>True when the focused window belongs to another program (never type into Krypta itself).</summary>
    public static bool ForeignWindowHasFocus()
    {
        IntPtr window = GetForegroundWindow();
        if (window == IntPtr.Zero) return false;
        GetWindowThreadProcessId(window, out uint processId);
        return processId != (uint)Environment.ProcessId;
    }

    /// <summary>Types the text; a tab character presses the Tab key to move to the next field.</summary>
    public static bool Type(string text)
    {
        var inputs = new List<Input>(text.Length * 2);
        foreach (char c in text)
        {
            bool tab = c == '\t';
            for (int phase = 0; phase < 2; phase++)
            {
                inputs.Add(new Input
                {
                    Type = InputKeyboard,
                    Data = new InputUnion
                    {
                        Keyboard = new KeyboardInput
                        {
                            Key = tab ? VkTab : (ushort)0,
                            Scan = tab ? (ushort)0 : c,
                            Flags = (tab ? 0 : Unicode) | (phase == 1 ? KeyUp : 0),
                        },
                    },
                });
            }
        }
        if (inputs.Count == 0) return true;
        var array = inputs.ToArray();
        uint sent = SendInput((uint)array.Length, array, Marshal.SizeOf<Input>());
        Array.Clear(array);
        return sent == array.Length;
    }
}

/// <summary>Light or dark appearance and the accent colour.</summary>
internal static class Appearance
{
    public static readonly (string Key, string Hex)[] Accents =
    [
        ("system", ""), ("blue", "#3B82F6"), ("green", "#22A06B"), ("violet", "#8B5CF6"), ("red", "#E5484D"), ("orange", "#F28C28"),
    ];

    private static readonly string[] AccentKeys =
    [
        "AccentTextFillColorPrimaryBrush", "AccentFillColorDefaultBrush", "AccentButtonBackground",
        "AccentButtonBackgroundPointerOver", "AccentButtonBackgroundPressed", "AccentButtonForeground",
        "AccentButtonForegroundPointerOver", "AccentButtonForegroundPressed",
    ];

    public static void Apply(string theme, string accent)
    {
        var app = Application.Current;
        app.ThemeMode = theme switch { "light" => ThemeMode.Light, "dark" => ThemeMode.Dark, _ => ThemeMode.System };

        foreach (string key in AccentKeys) app.Resources.Remove(key);
        string hex = Accents.FirstOrDefault(a => a.Key == accent).Hex ?? "";
        if (hex.Length == 0) return;

        var color = (Color)ColorConverter.ConvertFromString(hex);
        Brush Solid(Color c) { var brush = new SolidColorBrush(c); brush.Freeze(); return brush; }
        Color Mix(Color c, double white) => Color.FromRgb(
            (byte)(c.R + (255 - c.R) * white), (byte)(c.G + (255 - c.G) * white), (byte)(c.B + (255 - c.B) * white));

        app.Resources["AccentTextFillColorPrimaryBrush"] = Solid(Mix(color, 0.25));
        app.Resources["AccentFillColorDefaultBrush"] = Solid(color);
        app.Resources["AccentButtonBackground"] = Solid(color);
        app.Resources["AccentButtonBackgroundPointerOver"] = Solid(Mix(color, 0.12));
        app.Resources["AccentButtonBackgroundPressed"] = Solid(Mix(color, 0.22));
        foreach (string key in AccentKeys.Where(k => k.StartsWith("AccentButtonForeground", StringComparison.Ordinal)))
            app.Resources[key] = Brushes.White;
    }
}
