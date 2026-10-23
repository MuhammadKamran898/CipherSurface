using System.Text.Json;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace CipherSurface.Services;

public sealed record VerificationOptions
{
    /// <summary>Extra checks after the first, for DNS propagation. They do NOT consume attempts.</summary>
    public int DnsRetries { get; init; } = 2;
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(5);
    public int MaxAttemptsPerUserPerHour { get; init; } = 20;
    public int MaxAttemptsPerIpPerHour { get; init; } = 40;

    /// <summary>
    /// A click that has not finished after this long is treated as abandoned (a crash, a killed process), so a
    /// challenge can never stay stuck in Checking. While a click is younger than this, further clicks get "Busy".
    /// </summary>
    public TimeSpan CheckLease { get; init; } = TimeSpan.FromMinutes(2);
}

public sealed record VerifyResult(
    CheckOutcome Outcome, string Reason, ChallengeStatus ChallengeStatus, DomainStatus DomainStatus,
    bool DisputeOpened, int FailedAttempts, int MaxAttempts);

/// <summary>Handles one click on "Verify" for a DNS, HTTP-file or meta-tag challenge.</summary>
public sealed class VerificationService
{
    private sealed record Started(Guid AttemptId, VerificationMethod Method, string Host, string Token);

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
            var started = await StartAttemptAsync(actor, challengeId, ct);
            try
            {
                return await RunAndRecordAsync(actor, challengeId, started, ct);
            }
            catch (Exception)
            {
                // Whatever went wrong (verifier crash, cancellation, a lost race), do not leave the click hanging.
                await ReleaseAsync(started.AttemptId, challengeId);
                throw;
            }
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ServiceException("Busy", "This challenge is being checked right now. Try again in a moment.");
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: "23505" })
        {
            // The database refused a duplicate (for example a second evidence row). It already rolled back; report it plainly.
            throw new ServiceException("Busy", "This challenge was just completed by another request.");
        }
    }

    /// <summary>
    /// Step 1: validate and register the attempt. Everything is decided under a per-challenge advisory lock,
    /// so two clicks can never both start, and a re-read under the lock sees the other click's result.
    /// </summary>
    private async Task<Started> StartAttemptAsync(Actor actor, Guid challengeId, CancellationToken ct)
    {
        ServiceException? rejection = null;
        Started? started = null;

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            await Access.RequireManagerAsync(db, actor, ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, $"challenge:{challengeId:D}", ct);

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
                rejection = new ServiceException("ChallengeExpired", "This challenge has expired. Generate a new one.");
            }
            else
            {
                var failed = await db.VerificationAttempts
                    .CountAsync(a => a.ChallengeId == challengeId && a.Result == CheckOutcome.ProofAbsent, ct);
                if (failed >= challenge.MaxAttempts)
                {
                    challenge.Status = ChallengeStatus.Expired;
                    await db.SaveChangesAsync(ct);
                    rejection = new ServiceException("AttemptLimitReached", "Too many failed attempts. Generate a new challenge.");
                }
                else
                {
                    if (challenge.Status == ChallengeStatus.Checking)
                    {
                        var staleBefore = now - _options.CheckLease;
                        var pending = await db.VerificationAttempts
                            .Where(a => a.ChallengeId == challengeId && a.Result == null).ToListAsync(ct);
                        if (pending.Any(a => a.StartedAt > staleBefore))
                            throw new ServiceException("Busy", "This challenge is being checked right now. Try again in a moment.");

                        // Abandoned: close the old clicks as inconclusive (they never count as failures) and carry on.
                        foreach (var abandoned in pending) abandoned.Result = CheckOutcome.Inconclusive;
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
                    challenge.Status = ChallengeStatus.Checking;
                    await db.SaveChangesAsync(ct);

                    started = new Started(attempt.Id, challenge.Method, challenge.Host, challenge.Token);
                }
            }

            await tx.CommitAsync(ct);   // commit first, so a rejection that changed the challenge (expiry) is kept
        }

        if (rejection is not null) throw rejection;
        return started!;
    }

    /// <summary>Steps 2 and 3: run the verifier (no database connection held), then record and act on the result.</summary>
    private async Task<VerifyResult> RunAndRecordAsync(Actor actor, Guid challengeId, Started started, CancellationToken ct)
    {
        if (!_registry.TryGet(started.Method, out var verifier))
            throw new ServiceException("MethodNotSupported", $"No verifier is registered for {started.Method}.");

        var request = new VerificationRequest(started.Method, started.Host, started.Token);
        var observations = new List<VerificationObservation>();
        var maxChecks = started.Method == VerificationMethod.DnsTxt ? 1 + _options.DnsRetries : 1;
        for (var i = 0; i < maxChecks; i++)
        {
            if (i > 0) await _delay(_options.RetryDelay, ct);
            var observation = await verifier.CheckAsync(request, ct);
            observations.Add(observation);
            if (observation.Outcome == CheckOutcome.ProofValid) break;
        }
        var final = observations[^1];

        await using var db = await _factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var attempt = await db.VerificationAttempts.SingleAsync(a => a.Id == started.AttemptId, ct);
        var challenge = await db.VerificationChallenges.Include(c => c.Domain).SingleAsync(c => c.Id == challengeId, ct);
        var now = _time.GetUtcNow();

        for (var i = 0; i < observations.Count; i++)
        {
            db.VerificationChecks.Add(new VerificationCheck
            {
                Id = Guid.NewGuid(),
                AttemptId = started.AttemptId,
                RetryNumber = i,
                CheckedAt = now,
                Outcome = observations[i].Outcome,
                TriggeredBy = CheckTrigger.User,
                Detail = JsonSerializer.Serialize(new { reason = observations[i].Reason })
            });
        }
        attempt.Result = final.Outcome;

        var disputed = false;
        var failedAttempts = 0;
        if (final.Outcome == CheckOutcome.ProofValid)
        {
            var claim = await _claims.CompleteAsync(db, challenge, actor.UserId, actor.Ip, ct);
            disputed = claim.Disputed;
        }
        else
        {
            challenge.Status = ChallengeStatus.Issued;
            await db.SaveChangesAsync(ct);
            failedAttempts = await db.VerificationAttempts
                .CountAsync(a => a.ChallengeId == challengeId && a.Result == CheckOutcome.ProofAbsent, ct);
            if (final.Outcome == CheckOutcome.ProofAbsent && failedAttempts >= challenge.MaxAttempts)
            {
                challenge.Status = ChallengeStatus.Expired;   // 5 failed attempts: a new token is required
                await db.SaveChangesAsync(ct);
            }
        }

        await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "verification.attempt", "VerificationChallenge", challengeId,
            new Dictionary<string, object?>
            {
                ["method"] = started.Method.ToString(),
                ["outcome"] = final.Outcome.ToString(),
                ["reason"] = final.Reason,
                ["checks"] = observations.Count
            }, actor.Ip), ct);

        await tx.CommitAsync(ct);
        return new VerifyResult(final.Outcome, final.Reason, challenge.Status, challenge.Domain.Status, disputed, failedAttempts, challenge.MaxAttempts);
    }

    /// <summary>
    /// Best-effort cleanup after a failed click: close the attempt as inconclusive and put the challenge back to Issued,
    /// unless another click is genuinely in flight or the challenge was already completed. Never creates evidence.
    /// </summary>
    private async Task ReleaseAsync(Guid attemptId, Guid challengeId)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(CancellationToken.None);
            var attempt = await db.VerificationAttempts.SingleOrDefaultAsync(a => a.Id == attemptId, CancellationToken.None);
            if (attempt is { Result: null }) attempt.Result = CheckOutcome.Inconclusive;

            var challenge = await db.VerificationChallenges.SingleOrDefaultAsync(c => c.Id == challengeId, CancellationToken.None);
            if (challenge is { Status: ChallengeStatus.Checking })
            {
                var otherInFlight = await db.VerificationAttempts
                    .AnyAsync(a => a.ChallengeId == challengeId && a.Result == null && a.Id != attemptId, CancellationToken.None);
                if (!otherInFlight) challenge.Status = ChallengeStatus.Issued;
            }
            await db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception)
        {
            // Nothing more to do: the check lease lets the next click recover an abandoned challenge anyway.
        }
    }
}
