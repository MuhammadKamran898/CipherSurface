using System.Net;
using CipherSurface.Data.Enums;

namespace CipherSurface.Verification;

/// <summary>What a verifier is asked to look for. Host is the host where the proof was placed.</summary>
public sealed record VerificationRequest(VerificationMethod Method, string Host, string Token);

/// <summary>
/// A verifier only REPORTS what it observed. The service layer owns evidence state changes,
/// retries and audit records. Reason is a short code and never contains the token.
/// </summary>
public sealed record VerificationObservation(CheckOutcome Outcome, string Reason)
{
    public static VerificationObservation Valid(string reason = Reasons.ProofFound) => new(CheckOutcome.ProofValid, reason);
    public static VerificationObservation Absent(string reason) => new(CheckOutcome.ProofAbsent, reason);
    public static VerificationObservation Inconclusive(string reason) => new(CheckOutcome.Inconclusive, reason);
}

public static class Reasons
{
    public const string ProofFound = "ProofFound";
    public const string InvalidRequest = "InvalidRequest";
    public const string VerifierError = "VerifierError";

    // ProofAbsent: the lookup worked and the proof is missing or wrong.
    public const string TxtRecordMissing = "TxtRecordMissing";
    public const string TokenMismatch = "TokenMismatch";
    public const string NotFound = "NotFound";
    public const string HostNotFound = "HostNotFound";
    public const string ContentMismatch = "ContentMismatch";
    public const string RedirectRefused = "RedirectRefused";
    public const string TooManyRedirects = "TooManyRedirects";

    // Inconclusive: the system could not tell.
    public const string ResolverFailure = "ResolverFailure";
    public const string DestinationBlocked = "DestinationBlocked";
    public const string ConnectionFailure = "ConnectionFailure";
    public const string HttpStatusPrefix = "HttpStatus";
}

/// <summary>A method whose proof can be checked repeatedly (DNS, HTTP file, meta tag).</summary>
public interface IOwnershipVerifier
{
    VerificationMethod Method { get; }
    Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct);
}

public static class MethodTraits
{
    /// <summary>
    /// Admin-email is a one-time human confirmation with a 30-day expiry. There is nothing to
    /// observe, so it has no IOwnershipVerifier and the re-verification job must skip it.
    /// </summary>
    public static bool IsObservable(VerificationMethod method) =>
        method is VerificationMethod.DnsTxt or VerificationMethod.HttpFile or VerificationMethod.HtmlMeta;
}

public static class ProofFormat
{
    public const string DnsLabel = "_ciphersurface-verify";
    public const string ValuePrefix = "ciphersurface-verify=";
    public const string WellKnownPath = "/.well-known/ciphersurface-verify.txt";
    public const string MetaName = "ciphersurface-verify";

    public static string ExpectedValue(string token) => ValuePrefix + token;

    public static bool IsValidToken(string? token)
    {
        if (token is null || token.Length is < 16 or > 128) return false;
        foreach (var c in token)
        {
            var ok = c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_';
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>Lower-case DNS name with at least two labels. IP literals are rejected.</summary>
    public static bool IsValidHost(string? host) =>
        !string.IsNullOrWhiteSpace(host)
        && host.Length <= 253
        && host == host.Trim()
        && host == host.ToLowerInvariant()
        && host.Contains('.')
        && !host.StartsWith('.')
        && !host.EndsWith('.')
        && !IPAddress.TryParse(host, out _)
        && Uri.CheckHostName(host) == UriHostNameType.Dns;
}
