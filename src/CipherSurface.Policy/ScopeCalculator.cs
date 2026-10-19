using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Policy;

/// <summary>The live effective scope. Exclusions always override allowed patterns.</summary>
public sealed class EffectiveScope
{
    private readonly string _domainName;
    private readonly string[] _allowedPatterns;
    private readonly string[] _excludedPatterns;

    internal EffectiveScope(
        string domainName,
        IEnumerable<string> allowedPatterns,
        IEnumerable<string> excludedPatterns,
        IEnumerable<Guid> sourceEvidenceIds)
    {
        _domainName = domainName;
        _allowedPatterns = allowedPatterns.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        _excludedPatterns = excludedPatterns.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        SourceEvidenceIds = Array.AsReadOnly(sourceEvidenceIds.Distinct().OrderBy(x => x).ToArray());
        AllowedPatterns = Array.AsReadOnly(_allowedPatterns);
        ExcludedPatterns = Array.AsReadOnly(_excludedPatterns);
        Hash = ScopeCalculator.ComputeScopeHash(_domainName, _allowedPatterns, _excludedPatterns);
    }

    public string DomainName => _domainName;
    public IReadOnlyList<string> AllowedPatterns { get; }
    public IReadOnlyList<string> ExcludedPatterns { get; }
    public IReadOnlyList<Guid> SourceEvidenceIds { get; }
    public bool IsEmpty => _allowedPatterns.Length == 0;
    public string Hash { get; }

    public bool ContainsHost(string? host)
    {
        if (!HostPattern.TryNormalizeHost(host, out var normalized, out _))
            return false;
        if (!HostPattern.IsWithinDomain(normalized, _domainName))
            return false;

        var allowed = _allowedPatterns.Any(p => HostPattern.Matches(p, normalized));
        if (!allowed)
            return false;

        return !_excludedPatterns.Any(p => HostPattern.ExcludeMatches(p, normalized));
    }

    public string ToSnapshotJson()
    {
        var snapshot = new
        {
            domain = _domainName,
            allowedPatterns = _allowedPatterns,
            excludedPatterns = _excludedPatterns,
            sourceEvidenceIds = SourceEvidenceIds,
            scopeHash = Hash
        };
        return JsonSerializer.Serialize(snapshot, JsonOptions);
    }

    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

public sealed record ScopeCalculationResult(EffectiveScope? Scope, string? ErrorCode)
{
    public bool Succeeded => ErrorCode is null && Scope is not null;
}

/// <summary>
/// Pure scope algebra: (union of usable evidence ceilings intersect approved includes) minus exclusions.
/// It never performs DNS/HTTP, reads a database, or mutates input entities.
/// </summary>
public sealed class ScopeCalculator
{
    public ScopeCalculationResult Calculate(
        Guid domainId,
        string? domainName,
        IReadOnlyCollection<UsableEvidence> usableEvidence,
        IReadOnlyCollection<ScopeRule> scopeRules)
    {
        ArgumentNullException.ThrowIfNull(usableEvidence);
        ArgumentNullException.ThrowIfNull(scopeRules);

        if (!HostPattern.TryNormalizeHost(domainName, out var root, out _))
            return new ScopeCalculationResult(null, "InvalidDomainName");

        if (usableEvidence.Any(e => e.DomainId != domainId))
            return new ScopeCalculationResult(null, "EvidenceDomainMismatch");

        if (usableEvidence.Select(e => e.Id).Distinct().Count() != usableEvidence.Count)
            return new ScopeCalculationResult(null, "DuplicateEvidence");

        if (scopeRules.Any(r => r.DomainId != domainId))
            return new ScopeCalculationResult(null, "ScopeRuleDomainMismatch");

        var activeRules = scopeRules.Where(r => r.RemovedAt is null).ToArray();
        var parsedRules = new List<(ScopeRuleType Type, string Pattern)>();
        foreach (var rule in activeRules)
        {
            if (!Enum.IsDefined(rule.RuleType) ||
                !HostPattern.TryNormalizePattern(rule.Pattern, out var pattern, out _) ||
                !HostPattern.IsPatternWithinDomain(pattern, root))
            {
                return new ScopeCalculationResult(null, "InvalidScopeRule");
            }

            parsedRules.Add((rule.RuleType, pattern));
        }

        var ceilingPatterns = new List<string>();
        foreach (var evidence in usableEvidence)
        {
            if (!TryCreateCeilingPatterns(evidence, root, out var patterns, out var errorCode))
                return new ScopeCalculationResult(null, errorCode);
            ceilingPatterns.AddRange(patterns);
        }

        var includePatterns = parsedRules
            .Where(r => r.Type == ScopeRuleType.Include)
            .Select(r => r.Pattern)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var excludedPatterns = parsedRules
            .Where(r => r.Type == ScopeRuleType.Exclude)
            .Select(r => r.Pattern)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var allowedPatterns = new HashSet<string>(StringComparer.Ordinal);
        foreach (var include in includePatterns)
        foreach (var ceiling in ceilingPatterns)
        {
            var intersection = HostPattern.Intersect(include, ceiling);
            if (intersection is not null)
                allowedPatterns.Add(intersection);
        }

        var scope = new EffectiveScope(root, allowedPatterns, excludedPatterns, usableEvidence.Select(e => e.Id));
        return new ScopeCalculationResult(scope, null);
    }

    public static string ComputeScopeRulesHash(IEnumerable<ScopeRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var canonical = string.Join("\n", rules
            .Where(r => r.RemovedAt is null)
            .Select(r => $"{r.RuleType}:{(r.Pattern ?? string.Empty).Trim().ToLowerInvariant()}")
            .OrderBy(x => x, StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    internal static string ComputeScopeHash(string domainName, IEnumerable<string> allow, IEnumerable<string> exclude)
    {
        var canonical = string.Join("\n", new[] { domainName, "ALLOW", string.Join("\n", allow.OrderBy(x => x, StringComparer.Ordinal)), "EXCLUDE", string.Join("\n", exclude.OrderBy(x => x, StringComparer.Ordinal)) });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static bool TryCreateCeilingPatterns(
        UsableEvidence evidence,
        string root,
        out IReadOnlyList<string> patterns,
        out string? errorCode)
    {
        patterns = [];
        errorCode = null;

        if (!HostPattern.TryNormalizeHost(evidence.Host, out var host, out _))
        {
            errorCode = "InvalidEvidenceHost";
            return false;
        }
        if (!HostPattern.IsWithinDomain(host, root))
        {
            errorCode = "EvidenceHostOutsideDomain";
            return false;
        }

        if (!Enum.IsDefined(evidence.Method) || !Enum.IsDefined(evidence.ScopeCeilingType))
        {
            errorCode = "InvalidEvidenceCeiling";
            return false;
        }

        if (evidence.ScopeCeilingType == ScopeCeilingType.DomainAndSubdomains && evidence.Method != VerificationMethod.DnsTxt)
        {
            errorCode = "WildcardCeilingRequiresDns";
            return false;
        }

        if (evidence.Method == VerificationMethod.AdminEmail && evidence.ScopeCeilingType != ScopeCeilingType.RootOnly)
        {
            errorCode = "EmailEvidenceMustBeRootOnly";
            return false;
        }

        switch (evidence.ScopeCeilingType)
        {
            case ScopeCeilingType.DomainAndSubdomains:
                if (evidence.Method != VerificationMethod.DnsTxt || host != root)
                {
                    errorCode = "WildcardCeilingRequiresRootDnsProof";
                    return false;
                }
                // The root and all subdomains are within DNS-verified control.
                patterns = new[] { root, $"*.{root}" };
                return true;

            case ScopeCeilingType.ExactHost:
                patterns = new[] { host };
                return true;

            case ScopeCeilingType.RootOnly:
                if (host != root)
                {
                    errorCode = "RootOnlyEvidenceHostMustBeRoot";
                    return false;
                }
                // RootOnly evidence is meaningful only when proof is established at the root.
                patterns = new[] { root };
                return true;

            default:
                errorCode = "InvalidEvidenceCeiling";
                return false;
        }
    }
}

internal readonly record struct HostPatternValue(string Suffix, bool IsWildcard)
{
    public override string ToString() => IsWildcard ? $"*.{Suffix}" : Suffix;
}

internal static class HostPattern
{
    public static bool TryNormalizeHost(string? value, out string normalized, out string? error)
    {
        normalized = string.Empty;
        error = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            error = "EmptyHost";
            return false;
        }

        var candidate = value.Trim();
        // A single final dot is a valid DNS absolute-name notation. More than one is not.
        if (candidate.EndsWith(".", StringComparison.Ordinal))
            candidate = candidate[..^1];

        if (candidate.Length == 0 || candidate.Contains('*') || candidate.Contains('/') ||
            candidate.Contains('\\') || candidate.Contains(':') || candidate.Contains('@') ||
            candidate.Contains('?') || candidate.Contains('#') || candidate.Any(char.IsWhiteSpace))
        {
            error = "InvalidHostSyntax";
            return false;
        }

        try
        {
            var idn = new IdnMapping { UseStd3AsciiRules = true };
            candidate = idn.GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            error = "InvalidInternationalizedHost";
            return false;
        }

        if (candidate.Length > 253 || candidate.EndsWith(".", StringComparison.Ordinal) || IPAddress.TryParse(candidate, out _))
        {
            error = "InvalidHost";
            return false;
        }

        var labels = candidate.Split('.');
        if (labels.Length < 2 || labels.Any(label =>
                label.Length is < 1 or > 63 ||
                !IsAsciiAlphaNumeric(label[0]) ||
                !IsAsciiAlphaNumeric(label[^1]) ||
                label.Any(c => !(IsAsciiAlphaNumeric(c) || c == '-'))))
        {
            error = "InvalidDnsName";
            return false;
        }

        normalized = candidate;
        return true;
    }

    public static bool TryNormalizePattern(string? value, out string normalized, out string? error)
    {
        normalized = string.Empty;
        error = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            error = "EmptyPattern";
            return false;
        }

        var candidate = value.Trim();
        if (candidate.StartsWith("*.", StringComparison.Ordinal))
        {
            if (!TryNormalizeHost(candidate[2..], out var suffix, out error))
                return false;
            normalized = $"*.{suffix}";
            return true;
        }

        if (candidate.Contains('*'))
        {
            error = "InvalidWildcardPattern";
            return false;
        }

        return TryNormalizeHost(candidate, out normalized, out error);
    }

    public static bool IsWithinDomain(string host, string root) =>
        string.Equals(host, root, StringComparison.Ordinal) || host.EndsWith("." + root, StringComparison.Ordinal);

    public static bool IsPatternWithinDomain(string pattern, string root)
    {
        if (!TryParsePattern(pattern, out var parsed))
            return false;
        return IsWithinDomain(parsed.Suffix, root);
    }

    public static bool Matches(string pattern, string host)
    {
        if (!TryParsePattern(pattern, out var parsed))
            return false;
        return parsed.IsWildcard
            ? !string.Equals(host, parsed.Suffix, StringComparison.Ordinal) && IsWithinDomain(host, parsed.Suffix)
            : string.Equals(host, parsed.Suffix, StringComparison.Ordinal);
    }

    /// <summary>
    /// Exclusions fail closed: an exact exclusion removes the host AND everything beneath it
    /// (excluding admin.example.com also excludes deep.admin.example.com). A wildcard exclusion
    /// removes subdomains but, like wildcard includes, not the apex.
    /// </summary>
    public static bool ExcludeMatches(string pattern, string host)
    {
        if (!TryParsePattern(pattern, out var parsed))
            return true; // an unparseable exclusion must never silently allow a host
        return parsed.IsWildcard ? Matches(pattern, host) : IsWithinDomain(host, parsed.Suffix);
    }

    public static string? Intersect(string leftPattern, string rightPattern)
    {
        if (!TryParsePattern(leftPattern, out var left) || !TryParsePattern(rightPattern, out var right))
            return null;

        if (!left.IsWildcard && !right.IsWildcard)
            return left.Suffix == right.Suffix ? left.ToString() : null;

        if (!left.IsWildcard)
            return Matches(right.ToString(), left.Suffix) ? left.ToString() : null;

        if (!right.IsWildcard)
            return Matches(left.ToString(), right.Suffix) ? right.ToString() : null;

        if (left.Suffix == right.Suffix)
            return left.ToString();
        if (IsWithinDomain(left.Suffix, right.Suffix))
            return left.ToString(); // left is the narrower wildcard
        if (IsWithinDomain(right.Suffix, left.Suffix))
            return right.ToString(); // right is the narrower wildcard
        return null;
    }

    private static bool TryParsePattern(string value, out HostPatternValue parsed)
    {
        parsed = default;
        if (!TryNormalizePattern(value, out var normalized, out _))
            return false;
        if (normalized.StartsWith("*.", StringComparison.Ordinal))
            parsed = new HostPatternValue(normalized[2..], true);
        else
            parsed = new HostPatternValue(normalized, false);
        return true;
    }

    private static bool IsAsciiAlphaNumeric(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
