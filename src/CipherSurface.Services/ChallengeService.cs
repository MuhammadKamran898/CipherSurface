using System.Security.Cryptography;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public sealed record IssuedChallenge(
    Guid ChallengeId, VerificationMethod Method, string Host, string PlainToken, string Instruction, DateTimeOffset ExpiresAt);

public static class ChallengeTokens
{
    /// <summary>128-bit random token, base64url (22 characters). Public proof, so it is stored readable.</summary>
    public static string Generate() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Issues DNS, HTTP-file and meta-tag challenges. (Admin-email has its own flow.)</summary>
public sealed class ChallengeService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;

    public ChallengeService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
    }

    /// <summary>Issues a challenge. Any active challenge for the same domain and method is superseded.</summary>
    public async Task<IssuedChallenge> IssueAsync(Actor actor, Guid domainId, VerificationMethod method, string? host, CancellationToken ct)
    {
        if (!MethodTraits.IsObservable(method))
            throw new ServiceException("MethodNotSupported", "This method is not handled here.");

        await using var db = await _factory.CreateDbContextAsync(ct);
        await Access.RequireManagerAsync(db, actor, ct);
        var domain = await Access.LoadOwnDomainAsync(db, actor, domainId, ct);

        if (domain.Status is DomainStatus.Revoked or DomainStatus.Disputed)
            throw new ServiceException("DomainNotVerifiable", $"A {domain.Status} domain cannot be verified.");

        var proofHost = ResolveHost(domain.Name, method, host);
        var now = _time.GetUtcNow();

        await using var tx = await db.Database.BeginTransactionAsync(ct);

        // The partial unique index allows one active challenge per domain and method, so the old one
        // must be superseded and saved BEFORE the new one is inserted.
        var active = await db.VerificationChallenges
            .Where(c => c.DomainId == domain.Id && c.Method == method
                        && (c.Status == ChallengeStatus.Issued || c.Status == ChallengeStatus.Checking))
            .ToListAsync(ct);
        foreach (var old in active) old.Status = ChallengeStatus.Superseded;
        if (active.Count > 0) await db.SaveChangesAsync(ct);

        var challenge = new VerificationChallenge
        {
            Id = Guid.NewGuid(),
            DomainId = domain.Id,
            Method = method,
            Host = proofHost,
            Token = ChallengeTokens.Generate(),
            TokenIsHashed = false,
            Status = ChallengeStatus.Issued,
            MaxAttempts = ChallengeDefaultsForServices.MaxAttempts,
            IssuedAt = now,
            ExpiresAt = now + ChallengeDefaultsForServices.Lifetime
        };
        db.VerificationChallenges.Add(challenge);

        await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "challenge.issued", "VerificationChallenge", challenge.Id,
            new Dictionary<string, object?>
            {
                ["method"] = method.ToString(),
                ["host"] = proofHost,
                ["superseded"] = active.Count
            }, actor.Ip), ct);
        await tx.CommitAsync(ct);

        return new IssuedChallenge(challenge.Id, method, proofHost, challenge.Token, Instruction(method, proofHost, challenge.Token), challenge.ExpiresAt);
    }

    private static string ResolveHost(string domainName, VerificationMethod method, string? requested)
    {
        // DNS proof always lives at the domain itself (_ciphersurface-verify.<domain>).
        if (method == VerificationMethod.DnsTxt)
        {
            if (requested is not null && requested != domainName)
                throw new ServiceException("HostInvalid", "DNS verification must use the domain itself.");
            return domainName;
        }

        var host = requested ?? domainName;
        var inside = host == domainName || host.EndsWith("." + domainName, StringComparison.Ordinal);
        if (!inside || !ProofFormat.IsValidHost(host))
            throw new ServiceException("HostInvalid", "The host must be the domain or one of its subdomains.");
        return host;
    }

    private static string Instruction(VerificationMethod method, string host, string token) => method switch
    {
        VerificationMethod.DnsTxt =>
            $"Add a TXT record at {ProofFormat.DnsLabel}.{host} with the value {ProofFormat.ExpectedValue(token)}",
        VerificationMethod.HttpFile =>
            $"Serve https://{host}{ProofFormat.WellKnownPath} containing exactly: {ProofFormat.ExpectedValue(token)}",
        _ =>
            $"Add <meta name=\"{ProofFormat.MetaName}\" content=\"{token}\"> inside the <head> of https://{host}/"
    };
}

/// <summary>Challenge limits shared by every method (same values as the email flow).</summary>
internal static class ChallengeDefaultsForServices
{
    public static TimeSpan Lifetime => CipherSurface.Verification.Email.ChallengeDefaults.Lifetime;
    public static int MaxAttempts => CipherSurface.Verification.Email.ChallengeDefaults.MaxAttempts;
}
