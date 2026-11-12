using ZXing;
using ZXing.Common;

namespace Krypta.Core;

/// <summary>Finds QR codes in a raw BGRA image (a screenshot or a picture file).</summary>
public static class QrDecoder
{
    /// <summary>Returns the text of every QR code found. Pixels are 4 bytes each, BGRA, top-down.</summary>
    public static List<string> Decode(byte[] bgra, int width, int height)
    {
        var found = new List<string>();
        if (width <= 0 || height <= 0 || bgra.Length < width * height * 4) return found;

        DecodeRegion(bgra, width, height, found);
        if (found.Count > 0) return found;

        // A small code on a large screenshot can be missed; look at overlapping tiles too.
        foreach (int grid in new[] { 2, 3, 4 })
        {
            int tileW = Math.Min(width, width * 2 / (grid + 1));
            int tileH = Math.Min(height, height * 2 / (grid + 1));
            if (tileW < 64 || tileH < 64) break;
            for (int gy = 0; gy < grid; gy++)
            {
                for (int gx = 0; gx < grid; gx++)
                {
                    int x = grid == 1 ? 0 : (width - tileW) * gx / (grid - 1);
                    int y = grid == 1 ? 0 : (height - tileH) * gy / (grid - 1);
                    DecodeRegion(Crop(bgra, width, x, y, tileW, tileH), tileW, tileH, found);
                }
            }
            if (found.Count > 0) break;
        }
        return found;
    }

    private static void DecodeRegion(byte[] bgra, int width, int height, List<string> found)
    {
        var reader = new BarcodeReaderGeneric
        {
            AutoRotate = false,
            Options = new DecodingOptions
            {
                TryHarder = true,
                TryInverted = true,
                PossibleFormats = [BarcodeFormat.QR_CODE],
            },
        };
        var source = new RGBLuminanceSource(bgra, width, height, RGBLuminanceSource.BitmapFormat.BGRA32);
        Result[]? results = null;
        try { results = reader.DecodeMultiple(source); }
        catch (ReaderException) { }
        if (results is null || results.Length == 0)
        {
            Result? single = null;
            try { single = reader.Decode(source); }
            catch (ReaderException) { }
            if (single is not null) results = [single];
        }
        if (results is null) return;
        foreach (var result in results)
        {
            if (!string.IsNullOrEmpty(result?.Text) && !found.Contains(result.Text)) found.Add(result.Text);
        }
    }

    private static byte[] Crop(byte[] bgra, int width, int x, int y, int w, int h)
    {
        byte[] tile = new byte[w * h * 4];
        for (int row = 0; row < h; row++)
            Buffer.BlockCopy(bgra, ((y + row) * width + x) * 4, tile, row * w * 4, w * 4);
        return tile;
    }

    /// <summary>Renders a QR code as a BGRA image. Used by tests.</summary>
    public static byte[] Encode(string text, int size)
    {
        var matrix = new ZXing.QrCode.QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size);
        byte[] bgra = new byte[size * size * 4];
        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                byte value = matrix[x, y] ? (byte)0 : (byte)255;
                int i = (y * size + x) * 4;
                bgra[i] = bgra[i + 1] = bgra[i + 2] = value;
                bgra[i + 3] = 255;
            }
        }
        return bgra;
    }
}
