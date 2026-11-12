using System.Runtime.InteropServices;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Krypta.App.Services;

/// <summary>Grabs pixels for the QR scanner, from the screen or from a picture.</summary>
internal static class ScreenCapture
{
    private const int SmXVirtualScreen = 76, SmYVirtualScreen = 77, SmCxVirtualScreen = 78, SmCyVirtualScreen = 79;
    private const uint SrcCopy = 0x00CC0020;

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint Size;
        public int Width;
        public int Height;
        public ushort Planes;
        public ushort BitCount;
        public uint Compression;
        public uint SizeImage;
        public int XPelsPerMeter;
        public int YPelsPerMeter;
        public uint ClrUsed;
        public uint ClrImportant;
    }

    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern bool BitBlt(IntPtr dest, int x, int y, int w, int h, IntPtr src, int srcX, int srcY, uint rop);
    [DllImport("gdi32.dll")] private static extern int GetDIBits(IntPtr dc, IntPtr bitmap, uint start, uint lines, byte[] bits, ref BitmapInfoHeader info, uint usage);

    /// <summary>Captures all monitors as top-down BGRA pixels.</summary>
    public static (byte[] Bgra, int Width, int Height) CaptureAllScreens()
    {
        int x = GetSystemMetrics(SmXVirtualScreen), y = GetSystemMetrics(SmYVirtualScreen);
        int width = GetSystemMetrics(SmCxVirtualScreen), height = GetSystemMetrics(SmCyVirtualScreen);
        if (width <= 0 || height <= 0) return ([], 0, 0);

        IntPtr screen = GetDC(IntPtr.Zero);
        IntPtr memory = CreateCompatibleDC(screen);
        IntPtr bitmap = CreateCompatibleBitmap(screen, width, height);
        try
        {
            IntPtr previous = SelectObject(memory, bitmap);
            bool copied = BitBlt(memory, 0, 0, width, height, screen, x, y, SrcCopy);
            SelectObject(memory, previous);
            if (!copied) return ([], 0, 0);

            var info = new BitmapInfoHeader
            {
                Size = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
                Width = width,
                Height = -height, // negative = top-down rows
                Planes = 1,
                BitCount = 32,
            };
            byte[] pixels = new byte[width * height * 4];
            int lines = GetDIBits(memory, bitmap, 0, (uint)height, pixels, ref info, 0);
            return lines == height ? (pixels, width, height) : ([], 0, 0);
        }
        finally
        {
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(IntPtr.Zero, screen);
        }
    }

    /// <summary>Converts any WPF image (file, clipboard) to top-down BGRA pixels.</summary>
    public static (byte[] Bgra, int Width, int Height) FromBitmap(BitmapSource source)
    {
        var converted = new FormatConvertedBitmap(source, PixelFormats.Bgra32, null, 0);
        int width = converted.PixelWidth, height = converted.PixelHeight;
        byte[] pixels = new byte[width * height * 4];
        converted.CopyPixels(pixels, width * 4, 0);
        return (pixels, width, height);
    }
}
