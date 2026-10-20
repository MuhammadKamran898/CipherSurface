using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Verification.Email;

public enum EmailLinkState { Usable, WrongMethod, AlreadyUsed, NotActive, Expired, TooManyAttempts }

public enum EmailConfirmationResult { Confirmed, InvalidToken, WrongMethod, AlreadyUsed, NotActive, Expired, TooManyAttempts }

/// <summary>
/// Pure decisions for the email confirmation page. Nothing here changes state.
///
/// IMPORTANT for the web layer: email security scanners open links automatically. So the link
/// must open a page (GET) that only calls Preview and shows a Confirm button. Only the button's
/// POST may call Evaluate and, if Confirmed, consume the challenge. Each POST with a wrong token
/// must be stored as a VerificationAttempt so the attempt limit works.
/// </summary>
public static class EmailConfirmationPolicy
{
    /// <summary>Used by the GET page. Does not look at the token.</summary>
    public static EmailLinkState Preview(VerificationChallenge challenge, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (challenge.Method != VerificationMethod.AdminEmail) return EmailLinkState.WrongMethod;

        switch (challenge.Status)
        {
            case ChallengeStatus.Passed: return EmailLinkState.AlreadyUsed;
            case ChallengeStatus.Issued:
            case ChallengeStatus.Checking: break;
            default: return EmailLinkState.NotActive; // Failed, Expired, Superseded
        }

        if (now >= challenge.ExpiresAt) return EmailLinkState.Expired;
        if (challenge.Attempts.Count >= challenge.MaxAttempts) return EmailLinkState.TooManyAttempts;
        return EmailLinkState.Usable;
    }

    /// <summary>Used by the POST handler only.</summary>
    public static EmailConfirmationResult Evaluate(VerificationChallenge challenge, string? presentedToken, DateTimeOffset now)
    {
        var state = Preview(challenge, now);
        if (state != EmailLinkState.Usable)
        {
            return state switch
            {
                EmailLinkState.WrongMethod => EmailConfirmationResult.WrongMethod,
                EmailLinkState.AlreadyUsed => EmailConfirmationResult.AlreadyUsed,
                EmailLinkState.Expired => EmailConfirmationResult.Expired,
                EmailLinkState.TooManyAttempts => EmailConfirmationResult.TooManyAttempts,
                _ => EmailConfirmationResult.NotActive
            };
        }

        // A challenge that does not store a hash is misconfigured. Never accept it.
        if (!challenge.TokenIsHashed || !EmailTokens.Matches(presentedToken, challenge.Token))
            return EmailConfirmationResult.InvalidToken;

        return EmailConfirmationResult.Confirmed;
    }
}
