using System.Globalization;
using System.Reflection;

namespace CipherSurface.Services;

/// <summary>
/// The Public Suffix List (https://publicsuffix.org), parsed with the algorithm from its format specification: the
/// prevailing rule is an exception rule if one matches, otherwise the matching rule with the most labels, otherwise the
/// implicit rule "*". Names are compared in lower-case ASCII (punycode), the form DomainNameValidator produces.
/// Both the ICANN and the private section are used, so shared hosting suffixes such as github.io count as suffixes.
/// Built once, immutable, safe to share between threads.
/// </summary>
public sealed class PublicSuffixList : IPublicSuffixCheck
{
    public const string EmbeddedResourceName = "CipherSurface.Services.public_suffix_list.dat";
    public const string FetchCommand =
        "Invoke-WebRequest https://publicsuffix.org/list/public_suffix_list.dat -OutFile src/CipherSurface.Services/Data/public_suffix_list.dat";

    private readonly HashSet<string> _rules;        // "co.uk", "github.io", "com"
    private readonly HashSet<string> _wildcards;    // for "*.ck" the entry is "ck"
    private readonly HashSet<string> _exceptions;   // for "!www.ck" the entry is "www.ck"

    private PublicSuffixList(HashSet<string> rules, HashSet<string> wildcards, HashSet<string> exceptions)
    {
        _rules = rules;
        _wildcards = wildcards;
        _exceptions = exceptions;
    }

    /// <summary>How many rules were read (rules, wildcard rules and exception rules).</summary>
    public int RuleCount => _rules.Count + _wildcards.Count + _exceptions.Count;

    /// <summary>Reads the list. A rule that cannot be understood stops the load: a rule silently skipped would make a public suffix look registrable.</summary>
    public static PublicSuffixList Parse(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var wildcards = new HashSet<string>(StringComparer.Ordinal);
        var exceptions = new HashSet<string>(StringComparer.Ordinal);
        var idn = new IdnMapping();

        var lineNumber = 0;
        while (reader.ReadLine() is { } line)
        {
            lineNumber++;
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("//", StringComparison.Ordinal)) continue;

            // A rule is the first word on the line; anything after whitespace is ignored.
            var rule = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            var isException = rule.StartsWith('!');
            if (isException) rule = rule[1..];
            var isWildcard = rule.StartsWith("*.", StringComparison.Ordinal);
            if (isWildcard) rule = rule[2..];
            if (isException && isWildcard) throw Bad(lineNumber, trimmed);

            var ascii = ToAscii(rule, idn) ?? throw Bad(lineNumber, trimmed);
            (isException ? exceptions : isWildcard ? wildcards : rules).Add(ascii);
        }

        if (rules.Count + wildcards.Count + exceptions.Count == 0)
            throw new FormatException("The public suffix list contains no rules.");
        return new PublicSuffixList(rules, wildcards, exceptions);
    }

    /// <summary>Loads the list bundled into this assembly. Fails with the fix when the data file was never fetched.</summary>
    public static PublicSuffixList LoadEmbedded()
    {
        var assembly = typeof(PublicSuffixList).Assembly;
        using var stream = assembly.GetManifestResourceStream(EmbeddedResourceName)
            ?? throw new InvalidOperationException(
                "The Public Suffix List is not bundled. Fetch it once from the repository root and rebuild: " + FetchCommand);
        using var reader = new StreamReader(stream);
        return Parse(reader);
    }

    public static PublicSuffixList LoadFile(string path)
    {
        using var reader = new StreamReader(path);
        return Parse(reader);
    }

    /// <summary>True when the name is itself a public suffix (a place where anyone may register), such as com, co.uk or github.io.</summary>
    public bool IsPublicSuffix(string name) =>
        SuffixLabelCount(name, out var labels) is { } count && count == labels.Length;

    /// <summary>The public suffix of the name, or null when the name is not a valid host name.</summary>
    public string? GetPublicSuffix(string name) =>
        SuffixLabelCount(name, out var labels) is { } count ? string.Join('.', labels[^count..]) : null;

    /// <summary>The suffix plus one more label, or null when the name is itself a public suffix or invalid.</summary>
    public string? GetRegistrableDomain(string name) =>
        SuffixLabelCount(name, out var labels) is { } count && labels.Length > count ? string.Join('.', labels[^(count + 1)..]) : null;

    // ------------------------------------------------------------------ the algorithm

    private int? SuffixLabelCount(string? name, out string[] labels)
    {
        labels = [];
        if (string.IsNullOrWhiteSpace(name)) return null;
        var normalized = name.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.Length == 0) return null;
        var parts = normalized.Split('.');
        if (parts.Any(l => l.Length == 0)) return null;
        labels = parts;

        string Suffix(int count) => string.Join('.', parts[^count..]);

        // An exception rule prevails; the public suffix is that rule without its leftmost label.
        for (var count = parts.Length; count >= 1; count--)
            if (_exceptions.Contains(Suffix(count)))
                return count - 1;

        // Otherwise the matching rule with the most labels. A wildcard rule "*.x" matches any name of one more label under x.
        for (var count = parts.Length; count >= 1; count--)
        {
            if (_rules.Contains(Suffix(count))) return count;
            if (count >= 2 && _wildcards.Contains(Suffix(count - 1))) return count;
        }

        return 1;   // no rule matched: the implicit rule "*" makes the last label the public suffix
    }

    private static string? ToAscii(string rule, IdnMapping idn)
    {
        try
        {
            var labels = rule.Split('.');
            if (labels.Any(l => l.Length == 0)) return null;
            return string.Join('.', labels.Select(l => l.All(char.IsAscii) ? l.ToLowerInvariant() : idn.GetAscii(l).ToLowerInvariant()));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static FormatException Bad(int lineNumber, string line) =>
        new($"The public suffix list has a rule that cannot be read at line {lineNumber}: {line}");
}
