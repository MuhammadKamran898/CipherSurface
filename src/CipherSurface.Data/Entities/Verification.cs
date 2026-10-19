using CipherSurface.Data.Enums;

namespace CipherSurface.Data.Entities;

public class VerificationChallenge
{
    public Guid Id { get; set; }
    public Guid DomainId { get; set; }
    public VerificationMethod Method { get; set; }
    /// <summary>Host the proof must appear on (e.g. www.brightcart.com).</summary>
    public string Host { get; set; } = "";
    /// <summary>Plain token for DNS/HTTP/meta. SHA-256 hash for AdminEmail (see TokenIsHashed).</summary>
    public string Token { get; set; } = "";
    public bool TokenIsHashed { get; set; }
    public ChallengeStatus Status { get; set; } = ChallengeStatus.Issued;
    public int MaxAttempts { get; set; } = 5;
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public uint Version { get; set; }

    public Domain Domain { get; set; } = null!;
    public List<VerificationAttempt> Attempts { get; set; } = [];   // attempt count = Attempts.Count
    public VerificationEvidence? Evidence { get; set; }
}

/// <summary>One user click on "Verify". Internal DNS retries do not create attempts.</summary>
public class VerificationAttempt
{
    public Guid Id { get; set; }
    public Guid ChallengeId { get; set; }
    public Guid UserId { get; set; }
    public string Ip { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public CheckOutcome? Result { get; set; }      // null while the job is running

    public VerificationChallenge Challenge { get; set; } = null!;
    public List<VerificationCheck> Checks { get; set; } = [];
}

public class VerificationEvidence
{
    public Guid Id { get; set; }
    public Guid DomainId { get; set; }
    public Guid ChallengeId { get; set; }
    public VerificationMethod Method { get; set; }
    public AssuranceLevel Assurance { get; set; }
    public ScopeCeilingType ScopeCeilingType { get; set; }
    public string Host { get; set; } = "";
    public DateTimeOffset EstablishedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }         // AdminEmail only
    public DateTimeOffset? LastCheckedAt { get; set; }
    public DateTimeOffset? LastValidAt { get; set; }
    public DateTimeOffset? FailingSince { get; set; }      // set by the first ProofAbsent
    public EvidenceStatus Status { get; set; } = EvidenceStatus.Active;
    public uint Version { get; set; }

    public Domain Domain { get; set; } = null!;
    public VerificationChallenge Challenge { get; set; } = null!;
    public List<VerificationCheck> Checks { get; set; } = [];
}

/// <summary>Immutable history of every check. Exactly one of AttemptId / EvidenceId is set.</summary>
public class VerificationCheck
{
    public Guid Id { get; set; }
    public Guid? AttemptId { get; set; }          // user-triggered
    public Guid? EvidenceId { get; set; }         // system re-verification
    /// <summary>Stable key per system verification cycle (daily run or pre-scan check).</summary>
    public Guid? CheckRunId { get; set; }
    public int RetryNumber { get; set; }
    public DateTimeOffset CheckedAt { get; set; }
    public CheckOutcome Outcome { get; set; }
    public CheckTrigger TriggeredBy { get; set; }
    /// <summary>jsonb: resolver, observed value, HTTP status, final host. Never contains tokens.</summary>
    public string Detail { get; set; } = "{}";

    public VerificationAttempt? Attempt { get; set; }
    public VerificationEvidence? Evidence { get; set; }
}
