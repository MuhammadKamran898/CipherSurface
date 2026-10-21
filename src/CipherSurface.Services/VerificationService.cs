using System.Text.Json;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public sealed record VerificationOptions
{
    /// <summary>Extra checks after the first, for DNS propagation. They do NOT consume attempts.</summary>
    public int DnsRetries { get; init; } = 2;
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(5);
    public int MaxAttemptsPerUserPerHour { get; init; } = 20;
    public int MaxAttemptsPerIpPerHour { get; init; } = 40;
}

public sealed record VerifyResult(
    CheckOutcome Outcome, string Reason, ChallengeStatus ChallengeStatus, DomainStatus DomainStatus,
    bool DisputeOpened, int FailedAttempts, int MaxAttempts);

/// <summary>Handles one click on "Verify" for a DNS, HTTP-file or meta-tag challenge.</summary>
public sealed class VerificationService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly VerifierRegistry _registry;
    private readonly ClaimService _claims;
    private readonly AuditLogWriter _audit;
    private readonly VerificationOptions _options;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public VerificationService(
        IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, VerifierRegistry registry,
        ClaimService claims, AuditLogWriter audit, VerificationOptions? options = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _factory = factory;
        _time = time;
        _registry = registry;
        _claims = claims;
        _audit = audit;
        _options = options ?? new VerificationOptions();
        _delay = delay ?? Task.Delay;
    }

    public async Task<VerifyResult> VerifyAsync(Actor actor, Guid challengeId, CancellationToken ct)
    {
        try
        {
            // ---- 1. Validate and register the attempt (short transaction, no network) ----
            Guid attemptId;
            VerificationMethod method;
            string host, token;
            await using (var db = await _factory.CreateDbContextAsync(ct))
            {
                await Access.RequireManagerAsync(db, actor, ct);
                var challenge = await db.VerificationChallenges.Include(c => c.Domain)
                    .SingleOrDefaultAsync(c => c.Id == challengeId && c.Domain.OrganizationId == actor.OrganizationId, ct)
                    ?? throw new ServiceException("NotFound", "Challenge not found.");

                if (!MethodTraits.IsObservable(challenge.Method))
                    throw new ServiceException("MethodNotSupported", "This method is confirmed by email.");
                if (challenge.Status is not (ChallengeStatus.Issued or ChallengeStatus.Checking))
                    throw new ServiceException("ChallengeNotActive", "This challenge is no longer active. Generate a new one.");

                var now = _time.GetUtcNow();
                if (now >= challenge.ExpiresAt)
                {
                    challenge.Status = ChallengeStatus.Expired;
                    await db.SaveChangesAsync(ct);
                    throw new ServiceException("ChallengeExpired", "This challenge has expired. Generate a new one.");
                }

                var failed = await db.VerificationAttempts
                    .CountAsync(a => a.ChallengeId == challengeId && a.Result == CheckOutcome.ProofAbsent, ct);
                if (failed >= challenge.MaxAttempts)
                {
                    challenge.Status = ChallengeStatus.Expired;
                    await db.SaveChangesAsync(ct);
                    throw new ServiceException("AttemptLimitReached", "Too many failed attempts. Generate a new challenge.");
                }

                await AttemptRateLimit.EnsureAsync(db, actor, now, _options, ct);

                var attempt = new VerificationAttempt
                {
                    Id = Guid.NewGuid(),
                    ChallengeId = challenge.Id,
                    UserId = actor.UserId,
                    Ip = actor.Ip,
                    StartedAt = now
                };
                db.VerificationAttempts.Add(attempt);
                challenge.Status = ChallengeStatus.Checking;   // xmin concurrency: a second simultaneous click gets "Busy"
                await db.SaveChangesAsync(ct);

                attemptId = attempt.Id;
                method = challenge.Method;
                host = challenge.Host;
                token = challenge.Token;
            }

            // ---- 2. Run the verifier (network, no database connection held) ----
            if (!_registry.TryGet(method, out var verifier))
                throw new ServiceException("MethodNotSupported", $"No verifier is registered for {method}.");

            var request = new VerificationRequest(method, host, token);
            var observations = new List<VerificationObservation>();
            var maxChecks = method == VerificationMethod.DnsTxt ? 1 + _options.DnsRetries : 1;
            for (var i = 0; i < maxChecks; i++)
            {
                if (i > 0) await _delay(_options.RetryDelay, ct);
                var observation = await verifier.CheckAsync(request, ct);
                observations.Add(observation);
                if (observation.Outcome == CheckOutcome.ProofValid) break;
            }
            var final = observations[^1];

            // ---- 3. Record the result and act on it (one transaction) ----
            await using (var db = await _factory.CreateDbContextAsync(ct))
            await using (var tx = await db.Database.BeginTransactionAsync(ct))
            {
                var attempt = await db.VerificationAttempts.SingleAsync(a => a.Id == attemptId, ct);
                var challenge = await db.VerificationChallenges.Include(c => c.Domain).SingleAsync(c => c.Id == challengeId, ct);
                var now = _time.GetUtcNow();

                for (var i = 0; i < observations.Count; i++)
                {
                    db.VerificationChecks.Add(new VerificationCheck
                    {
                        Id = Guid.NewGuid(),
                        AttemptId = attemptId,
                        RetryNumber = i,
                        CheckedAt = now,
                        Outcome = observations[i].Outcome,
                        TriggeredBy = CheckTrigger.User,
                        Detail = JsonSerializer.Serialize(new { reason = observations[i].Reason })
                    });
                }
                attempt.Result = final.Outcome;

                var disputed = false;
                var failed = 0;
                if (final.Outcome == CheckOutcome.ProofValid)
                {
                    var claim = await _claims.CompleteAsync(db, challenge, actor.UserId, actor.Ip, ct);
                    disputed = claim.Disputed;
                }
                else
                {
                    challenge.Status = ChallengeStatus.Issued;
                    await db.SaveChangesAsync(ct);
                    failed = await db.VerificationAttempts
                        .CountAsync(a => a.ChallengeId == challengeId && a.Result == CheckOutcome.ProofAbsent, ct);
                    if (final.Outcome == CheckOutcome.ProofAbsent && failed >= challenge.MaxAttempts)
                    {
                        challenge.Status = ChallengeStatus.Expired;   // 5 failed attempts: a new token is required
                        await db.SaveChangesAsync(ct);
                    }
                }

                await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "verification.attempt", "VerificationChallenge", challengeId,
                    new Dictionary<string, object?>
                    {
                        ["method"] = method.ToString(),
                        ["outcome"] = final.Outcome.ToString(),
                        ["reason"] = final.Reason,
                        ["checks"] = observations.Count
                    }, actor.Ip), ct);

                await tx.CommitAsync(ct);
                return new VerifyResult(final.Outcome, final.Reason, challenge.Status, challenge.Domain.Status, disputed, failed, challenge.MaxAttempts);
            }
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ServiceException("Busy", "This challenge is being checked right now. Try again in a moment.");
        }
    }
}
