namespace CipherSurface.Verification.Email;

public sealed record EmailMessage(string To, string Subject, string TextBody);

public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken ct);
}

public static class ConfirmationEmail
{
    /// <summary>
    /// Builds the message. The link opens a page with a Confirm button; it does not confirm by itself.
    /// The recipient must already have passed AdminMailboxes.IsAllowed.
    /// </summary>
    public static EmailMessage Build(string toAddress, string rootDomain, Uri confirmationPage, Guid challengeId, string plainToken, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toAddress);
        ArgumentException.ThrowIfNullOrWhiteSpace(plainToken);
        ArgumentNullException.ThrowIfNull(confirmationPage);
        if (!confirmationPage.IsAbsoluteUri || confirmationPage.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("The confirmation page must be an absolute https URL.", nameof(confirmationPage));

        var link = $"{confirmationPage.GetLeftPart(UriPartial.Path)}?c={challengeId:D}&t={Uri.EscapeDataString(plainToken)}";

        var body =
            $"Someone asked to verify ownership of {rootDomain} on CipherSurface using this mailbox.\n\n" +
            $"To continue, open this link and press the Confirm button:\n{link}\n\n" +
            $"The link expires at {expiresAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC and can be used once.\n\n" +
            "If you did not expect this, ignore this email. Nothing happens unless the button is pressed.";

        return new EmailMessage(toAddress, $"Confirm ownership of {rootDomain}", body);
    }
}
