using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;

namespace Krypta.App.Services;

/// <summary>
/// Measures that make it harder for other programs running as the same user (for example
/// info-stealer malware) to read secrets out of Krypta. They raise the bar; they cannot stop
/// malware that runs with administrator rights.
/// </summary>
internal static class Hardening
{
    private const uint DaclSecurityInformation = 0x4;
    private const uint WdaNone = 0x0;
    private const uint WdaExcludeFromCapture = 0x11;

    /// <summary>When true, Krypta windows are left out of screenshots and screen recordings.</summary>
    public static bool BlockScreenCapture { get; set; } = true;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(IntPtr handle, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    /// <summary>
    /// Replaces the access list of this process so that other programs of the same user can no
    /// longer open it to read its memory, inject code or attach a debugger. They may only see
    /// that it exists, wait for it, and end it.
    /// </summary>
    public static bool ProtectProcess()
    {
        if (Debugger.IsAttached) return false;
        string? sid = WindowsIdentity.GetCurrent().User?.Value;
        if (sid is null) return false;

        // 0x101001 = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
        string sddl = $"D:P(A;;0x101001;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out IntPtr descriptor, out _)) return false;
        try
        {
            return SetKernelObjectSecurity(GetCurrentProcess(), DaclSecurityInformation, descriptor);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>Applies the screen-capture setting to a window, now and whenever its handle is created.</summary>
    public static void Protect(Window window)
    {
        void Apply()
        {
            IntPtr hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd != IntPtr.Zero) SetWindowDisplayAffinity(hwnd, BlockScreenCapture ? WdaExcludeFromCapture : WdaNone);
        }
        window.SourceInitialized += (_, _) => Apply();
        Apply();
    }

    /// <summary>Forces a window out of (or back into) screen captures, regardless of the setting.</summary>
    public static void SetCaptureExcluded(Window window, bool excluded)
    {
        IntPtr hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd != IntPtr.Zero)
            SetWindowDisplayAffinity(hwnd, excluded || BlockScreenCapture ? WdaExcludeFromCapture : WdaNone);
    }

    /// <summary>Time since the last keyboard or mouse input anywhere in the session.</summary>
    public static TimeSpan IdleTime()
    {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.Time));
    }
}
