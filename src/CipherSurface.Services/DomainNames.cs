using System.Globalization;
using CipherSurface.Verification;

namespace CipherSurface.Services;

public interface IPublicSuffixCheck
{
    bool IsPublicSuffix(string name);
}

/// <summary>
/// PLACEHOLDER with a few well-known entries. Replace with a real Public Suffix List package
/// before production; the interface stays the same.
/// </summary>
public sealed class BasicPublicSuffixCheck : IPublicSuffixCheck
{
    private static readonly HashSet<string> Suffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp", "co.nz",
        "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "com.br", "com.cn", "co.za",
        "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
        "blogspot.com", "appspot.com", "web.app", "firebaseapp.com", "azurewebsites.net", "cloudfront.net"
    };

    public bool IsPublicSuffix(string name) => Suffixes.Contains(name);
}

public sealed class DomainNameValidator
{
    private static readonly string[] ReservedSuffixes = { "localhost", "local", "internal", "lan", "test", "invalid", "home.arpa" };
    private readonly IPublicSuffixCheck _publicSuffixes;

    public DomainNameValidator(IPublicSuffixCheck? publicSuffixes = null) =>
        _publicSuffixes = publicSuffixes ?? new BasicPublicSuffixCheck();

    /// <summary>Returns the lower-case ASCII form, or throws ServiceException.</summary>
    public string Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw Invalid("Enter a domain name.");

        var name = input.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Any(c => char.IsWhiteSpace(c) || c is '/' or ':' or '@' or '?' or '#' or '*' or '\\'))
            throw Invalid("Enter only the domain name, for example example.com.");

        try
        {
            name = new IdnMapping().GetAscii(name);
        }
        catch (ArgumentException)
        {
            throw Invalid("This is not a valid domain name.");
        }

        if (!ProofFormat.IsValidHost(name))
            throw Invalid("This is not a valid domain name.");

        foreach (var suffix in ReservedSuffixes)
        {
            if (name == suffix || name.EndsWith("." + suffix, StringComparison.Ordinal))
                throw Invalid("Local and reserved names cannot be verified.");
        }

        if (_publicSuffixes.IsPublicSuffix(name))
            throw new ServiceException("DomainIsPublicSuffix", "This is a shared public suffix, not a domain anyone owns.");

        return name;
    }

    private static ServiceException Invalid(string message) => new("DomainInvalid", message);
}
