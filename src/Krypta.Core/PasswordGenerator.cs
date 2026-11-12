using System.Security.Cryptography;

namespace Krypta.Core;

public sealed class PasswordOptions
{
    public int Length { get; set; } = 20;
    public bool Upper { get; set; } = true;
    public bool Lower { get; set; } = true;
    public bool Digits { get; set; } = true;
    public bool Symbols { get; set; } = true;
    /// <summary>Leave out characters that are easy to confuse, such as l, 1, I, O and 0.</summary>
    public bool ExcludeAmbiguous { get; set; }
}

public static class PasswordGenerator
{
    public const int MinLength = 4;
    public const int MaxLength = 128;

    private const string UpperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowerChars = "abcdefghijklmnopqrstuvwxyz";
    private const string DigitChars = "0123456789";
    private const string SymbolChars = "!@#$%^&*()-_=+[]{};:,.?/";
    private const string Ambiguous = "Il1O0o|";

    private static List<string> Classes(PasswordOptions o)
    {
        var classes = new List<string>();
        if (o.Upper) classes.Add(UpperChars);
        if (o.Lower) classes.Add(LowerChars);
        if (o.Digits) classes.Add(DigitChars);
        if (o.Symbols) classes.Add(SymbolChars);
        if (classes.Count == 0) classes.Add(LowerChars);
        if (o.ExcludeAmbiguous)
            classes = classes.Select(c => new string(c.Where(ch => !Ambiguous.Contains(ch)).ToArray())).ToList();
        return classes;
    }

    /// <summary>
    /// Generates a password from the operating system's cryptographic random source.
    /// Every selected character class appears at least once.
    /// </summary>
    public static string Generate(PasswordOptions options)
    {
        var classes = Classes(options);
        int length = Math.Clamp(options.Length, Math.Max(MinLength, classes.Count), MaxLength);
        string pool = string.Concat(classes);

        var chars = new char[length];
        int i = 0;
        foreach (string cls in classes) chars[i++] = cls[RandomNumberGenerator.GetInt32(cls.Length)];
        for (; i < length; i++) chars[i] = pool[RandomNumberGenerator.GetInt32(pool.Length)];

        RandomNumberGenerator.Shuffle<char>(chars);
        var result = new string(chars);
        Array.Clear(chars);
        return result;
    }

    /// <summary>Entropy in bits of a password generated with these options.</summary>
    public static double EntropyBits(PasswordOptions options)
    {
        var classes = Classes(options);
        int length = Math.Clamp(options.Length, Math.Max(MinLength, classes.Count), MaxLength);
        return length * Math.Log2(classes.Sum(c => c.Length));
    }

    /// <summary>
    /// Rough strength estimate for a password a person typed (0 = very weak … 4 = very strong).
    /// It only looks at length and character variety, so it overrates dictionary words.
    /// </summary>
    public static int EstimateStrength(string password)
    {
        if (string.IsNullOrEmpty(password)) return 0;
        int pool = 0;
        if (password.Any(char.IsLower)) pool += 26;
        if (password.Any(char.IsUpper)) pool += 26;
        if (password.Any(char.IsDigit)) pool += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) pool += 32;
        int distinct = password.Distinct().Count();
        double bits = Math.Min(password.Length, distinct * 2) * Math.Log2(Math.Max(pool, 2));
        return bits switch
        {
            < 40 => 0,
            < 60 => 1,
            < 80 => 2,
            < 100 => 3,
            _ => 4,
        };
    }
}
