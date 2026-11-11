namespace CipherSurface.Services;

/// <summary>
/// The authorization statement a user accepts when adding a domain. The SERVER owns the text: the client only says
/// which version it was shown and that it was accepted. The stored hash is therefore always the hash of the text the
/// user could actually read, never of something the client typed.
///
/// Changing the text REQUIRES a new CurrentVersion, so an earlier acceptance never silently carries over to a revised
/// statement. AttestationStatementTests pins the version together with the hash of the text and fails if only one changes.
/// The wording must be approved by the project supervisor before production use.
/// </summary>
public static class AttestationStatement
{
    public const string CurrentVersion = "2026-11-v2";

    public const string Text =
        "I confirm that I am authorized to act for my organization, and that my organization owns this domain or has " +
        "the permission of its owner to monitor it. I understand that proving ownership may involve a limited number of " +
        "DNS queries and HTTP requests made by CipherSurface solely to check the proof method I choose. I understand that, " +
        "after the domain is verified, CipherSurface will only collect information that is publicly available about this " +
        "domain and its subdomains, using passive methods, within the scope I define, and that I can revoke this " +
        "authorization at any time.";
}
