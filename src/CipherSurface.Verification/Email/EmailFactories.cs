using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Verification.Email;

public static class ChallengeDefaults
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(48);
    public const int MaxAttempts = 5;
}

public static class EmailChallengeFactory
{
    /// <summary>
    /// Returns the challenge to store (token hashed) and the plain token to put in the email.
    /// The plain token is never stored or logged.
    /// </summary>
    public static (VerificationChallenge Challenge, string PlainToken) Issue(Guid domainId, string rootDomain, DateTimeOffset now)
    {
        var plain = EmailTokens.Generate();
        var challenge = new VerificationChallenge
        {
            Id = Guid.NewGuid(),
            DomainId = domainId,
            Method = VerificationMethod.AdminEmail,
            Host = rootDomain,
            Token = EmailTokens.Hash(plain),
            TokenIsHashed = true,
            Status = ChallengeStatus.Issued,
            MaxAttempts = ChallengeDefaults.MaxAttempts,
            IssuedAt = now,
            ExpiresAt = now + ChallengeDefaults.Lifetime
        };
        return (challenge, plain);
    }
}

public static class EmailEvidenceFactory
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);

    /// <summary>Evidence created when a confirmation succeeds. Low assurance, root domain only, expires.</summary>
    public static VerificationEvidence Create(VerificationChallenge challenge, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        return new VerificationEvidence
        {
            Id = Guid.NewGuid(),
            DomainId = challenge.DomainId,
            ChallengeId = challenge.Id,
            Method = VerificationMethod.AdminEmail,
            Assurance = AssuranceLevel.Low,
            ScopeCeilingType = ScopeCeilingType.RootOnly,
            Host = challenge.Host,
            EstablishedAt = now,
            ExpiresAt = now + Lifetime,
            LastCheckedAt = now,
            LastValidAt = now,
            FailingSince = null,
            Status = EvidenceStatus.Active
        };
    }
}
