// Bridge between the browser extension and the running Krypta app.
// The browser starts this program and talks to it over stdin/stdout ("native messaging":
// a 4-byte length followed by JSON). Each message is passed to Krypta through a named pipe
// that only the current Windows user can open, and the answer is passed back.

using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

const int MaxMessageSize = 1024 * 1024;
const string NotRunning = """{"ok":false,"fallback":true,"error":"not-running"}""";

using var stdin = Console.OpenStandardInput();
using var stdout = Console.OpenStandardOutput();

byte[] lengthBytes = new byte[4];
while (await ReadExactAsync(stdin, lengthBytes))
{
    int length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
    if (length is <= 0 or > MaxMessageSize) return 1;
    byte[] request = new byte[length];
    if (!await ReadExactAsync(stdin, request)) return 1;

    byte[] response;
    try
    {
        response = await ForwardAsync(request);
    }
    catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException)
    {
        response = Encoding.UTF8.GetBytes(NotRunning);
    }

    BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, response.Length);
    await stdout.WriteAsync(lengthBytes);
    await stdout.WriteAsync(response);
    await stdout.FlushAsync();
}
return 0;

static async Task<byte[]> ForwardAsync(byte[] request)
{
    string pipeName = "Krypta.Passkeys.v1." + WindowsIdentity.GetCurrent().User!.Value;
    await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    await pipe.ConnectAsync(1500);

    await pipe.WriteAsync(request);
    await pipe.WriteAsync("\n"u8.ToArray());
    await pipe.FlushAsync();

    // The app answers with one line of JSON; it may wait for the user to confirm.
    using var buffer = new MemoryStream();
    byte[] chunk = new byte[8192];
    using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
    while (true)
    {
        int read = await pipe.ReadAsync(chunk, timeout.Token);
        if (read == 0) break;
        int newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
        buffer.Write(chunk, 0, newline >= 0 ? newline : read);
        if (newline >= 0) break;
        if (buffer.Length > MaxMessageSize) throw new IOException("Response too large.");
    }
    if (buffer.Length == 0) throw new IOException("Empty response.");
    return buffer.ToArray();
}

static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer)
{
    int offset = 0;
    while (offset < buffer.Length)
    {
        int read = await stream.ReadAsync(buffer.AsMemory(offset));
        if (read == 0) return false;
        offset += read;
    }
    return true;
}
