using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification.Email;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace CipherSurface.Services;

public sealed record EmailVerificationOptions
{
    /// <summary>Limits emails per domain (the five role mailboxes all belong to one domain).</summary>
    public int MaxEmailsPerDomainPerHour { get; init; } = 3;
    public int MaxEmailsPerDomainPerDay { get; init; } = 10;
}

public sealed record IssuedEmailChallenge(Guid ChallengeId, string Recipient, DateTimeOffset ExpiresAt);
public sealed record EmailLinkPreview(EmailLinkState State, string DomainName);
public sealed record EmailConfirmResult(DomainStatus DomainStatus, bool DisputeOpened);

/// <summary>
/// Admin-email verification. The person confirming must be logged in as an Owner or Admin of the
/// organization that owns the domain, so every confirmation is tied to a known user.
/// The link opens a page that calls PreviewAsync (no state change); only the Confirm button's POST
/// calls ConfirmAsync, so email scanners that open links cannot use up the token.
/// </summary>
public sealed class EmailVerificationService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly ClaimService _claims;
    private readonly AuditLogWriter _audit;
    private readonly IEmailSender _sender;
    private readonly EmailVerificationOptions _emailOptions;
    private readonly VerificationOptions _attemptOptions;

    public EmailVerificationService(
        IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, ClaimService claims, AuditLogWriter audit,
        IEmailSender sender, EmailVerificationOptions? emailOptions = null, VerificationOptions? attemptOptions = null)
    {
        _factory = factory;
        _time = time;
        _claims = claims;
        _audit = audit;
        _sender = sender;
        _emailOptions = emailOptions ?? new EmailVerificationOptions();
        _attemptOptions = attemptOptions ?? new VerificationOptions();
    }

    public async Task<IssuedEmailChallenge> IssueAsync(Actor actor, Guid domainId, string recipient, Uri confirmationPage, CancellationToken ct)
    {
        Guid challengeId;
        string plainToken;
        DateTimeOffset expiresAt;
        string domainName;
        var to = (recipient ?? string.Empty).Trim().ToLowerInvariant();

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            await Access.RequireManagerAsync(db, actor, ct);
            var domain = await Access.LoadOwnDomainAsync(db, actor, domainId, ct);
            if (domain.Status is DomainStatus.Revoked or DomainStatus.Disputed)
                throw new ServiceException("DomainNotVerifiable", $"A {domain.Status} domain cannot be verified.");
            if (!AdminMailboxes.IsAllowed(to, domain.Name))
                throw new ServiceException("RecipientNotAllowed", "Choose one of the standard role mailboxes on this exact domain.");

            var now = _time.GetUtcNow();
            var lastHour = await db.VerificationChallenges.CountAsync(c =>
                c.DomainId == domain.Id && c.Method == VerificationMethod.AdminEmail && c.IssuedAt > now.AddHours(-1), ct);
            var lastDay = await db.VerificationChallenges.CountAsync(c =>
                c.DomainId == domain.Id && c.Method == VerificationMethod.AdminEmail && c.IssuedAt > now.AddDays(-1), ct);
            if (lastHour >= _emailOptions.MaxEmailsPerDomainPerHour || lastDay >= _emailOptions.MaxEmailsPerDomainPerDay)
                throw new ServiceException("RateLimited", "Too many verification emails for this domain. Try again later.");

            await using var tx = await db.Database.BeginTransactionAsync(ct);

            var active = await db.VerificationChallenges
                .Where(c => c.DomainId == domain.Id && c.Method == VerificationMethod.AdminEmail
                            && (c.Status == ChallengeStatus.Issued || c.Status == ChallengeStatus.Checking))
                .ToListAsync(ct);
            foreach (var old in active) old.Status = ChallengeStatus.Superseded;
            if (active.Count > 0) await db.SaveChangesAsync(ct);

            var (challenge, plain) = EmailChallengeFactory.Issue(domain.Id, domain.Name, now);
            db.VerificationChallenges.Add(challenge);

            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "challenge.issued", "VerificationChallenge", challenge.Id,
                new Dictionary<string, object?>
                {
                    ["method"] = VerificationMethod.AdminEmail.ToString(),
                    ["recipient"] = to,
                    ["superseded"] = active.Count
                }, actor.Ip), ct);
            await tx.CommitAsync(ct);

            challengeId = challenge.Id;
            plainToken = plain;
            expiresAt = challenge.ExpiresAt;
            domainName = domain.Name;
        }

        // Send after the commit. If sending fails, the challenge is closed so a link nobody received stays unusable.
        try
        {
            await _sender.SendAsync(ConfirmationEmail.Build(to, domainName, confirmationPage, challengeId, plainToken, expiresAt), ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            var challenge = await db.VerificationChallenges.SingleAsync(c => c.Id == challengeId, ct);
            challenge.Status = ChallengeStatus.Failed;
            await db.SaveChangesAsync(ct);
            throw new ServiceException("EmailSendFailed", "The verification email could not be sent.");
        }

        return new IssuedEmailChallenge(challengeId, to, expiresAt);
    }

    /// <summary>For the page the link opens (HTTP GET). Never changes anything.</summary>
    public async Task<EmailLinkPreview> PreviewAsync(Actor actor, Guid challengeId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await Access.RequireManagerAsync(db, actor, ct);
        var challenge = await LoadAsync(db, actor, challengeId, ct);
        return new EmailLinkPreview(EmailConfirmationPolicy.Preview(challenge, _time.GetUtcNow()), challenge.Domain.Name);
    }

    /// <summary>For the Confirm button (HTTP POST).</summary>
    public async Task<EmailConfirmResult> ConfirmAsync(Actor actor, Guid challengeId, string? presentedToken, CancellationToken ct)
    {
        ServiceException? failure = null;
        EmailConfirmResult? success = null;

        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await Access.RequireManagerAsync(db, actor, ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);

            var challenge = await LoadAsync(db, actor, challengeId, ct);
            var now = _time.GetUtcNow();

            var state = EmailConfirmationPolicy.Preview(challenge, now);
            if (state != EmailLinkState.Usable)
            {
                failure = await RejectUnusableAsync(db, challenge, state, ct);
            }
            else
            {
                await AttemptRateLimit.EnsureAsync(db, actor, now, _attemptOptions, ct);

                // Evaluate BEFORE recording this attempt, so the fifth wrong token is still judged normally.
                var evaluation = EmailConfirmationPolicy.Evaluate(challenge, presentedToken, now);
                var attempt = new VerificationAttempt
                {
                    Id = Guid.NewGuid(),
                    ChallengeId = challenge.Id,
                    UserId = actor.UserId,
                    Ip = actor.Ip,
                    StartedAt = now
                };
                db.VerificationAttempts.Add(attempt);

                var confirmed = evaluation == EmailConfirmationResult.Confirmed;
                attempt.Result = confirmed ? CheckOutcome.ProofValid : CheckOutcome.ProofAbsent;
                db.VerificationChecks.Add(new VerificationCheck
                {
                    Id = Guid.NewGuid(),
                    AttemptId = attempt.Id,
                    RetryNumber = 0,
                    CheckedAt = now,
                    Outcome = attempt.Result.Value,
                    TriggeredBy = CheckTrigger.User,
                    Detail = JsonSerializer.Serialize(new { reason = confirmed ? "EmailConfirmed" : evaluation.ToString() })
                });

                if (confirmed)
                {
                    var claim = await _claims.CompleteAsync(db, challenge, actor.UserId, actor.Ip, ct);
                    success = new EmailConfirmResult(challenge.Domain.Status, claim.Disputed);
                }
                else
                {
                    if (challenge.Attempts.Count >= challenge.MaxAttempts)
                        challenge.Status = ChallengeStatus.Expired;      // five wrong tokens: a new email is required
                    await db.SaveChangesAsync(ct);
                    failure = new ServiceException("InvalidToken", "The confirmation link is not valid.");
                }

                await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "verification.attempt", "VerificationChallenge", challengeId,
                    new Dictionary<string, object?>
                    {
                        ["method"] = VerificationMethod.AdminEmail.ToString(),
                        ["outcome"] = attempt.Result.Value.ToString()
                    }, actor.Ip), ct);
            }

            await tx.CommitAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ServiceException("Busy", "This confirmation is being processed. Try again in a moment.");
        }
        catch (DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
        {
            throw new ServiceException("Busy", "This confirmation was just completed by another request.");
        }

        if (failure is not null) throw failure;
        return success!;
    }

    private static async Task<VerificationChallenge> LoadAsync(CipherSurfaceDbContext db, Actor actor, Guid challengeId, CancellationToken ct) =>
        await db.VerificationChallenges.Include(c => c.Domain).Include(c => c.Attempts)
            .SingleOrDefaultAsync(c => c.Id == challengeId
                                       && c.Method == VerificationMethod.AdminEmail
                                       && c.Domain.OrganizationId == actor.OrganizationId, ct)
        ?? throw new ServiceException("NotFound", "Confirmation link not found.");

    private static async Task<ServiceException> RejectUnusableAsync(CipherSurfaceDbContext db, VerificationChallenge challenge, EmailLinkState state, CancellationToken ct)
    {
        switch (state)
        {
            case EmailLinkState.Expired:
                challenge.Status = ChallengeStatus.Expired;
                await db.SaveChangesAsync(ct);
                return new ServiceException("ChallengeExpired", "This link has expired. Request a new email.");
            case EmailLinkState.TooManyAttempts:
                challenge.Status = ChallengeStatus.Expired;
                await db.SaveChangesAsync(ct);
                return new ServiceException("AttemptLimitReached", "Too many wrong attempts. Request a new email.");
            case EmailLinkState.WrongMethod:
                return new ServiceException("MethodNotSupported", "This challenge is not an email challenge.");
            default:
                return new ServiceException("ChallengeNotActive", "This link was already used or replaced.");
        }
    }
}
