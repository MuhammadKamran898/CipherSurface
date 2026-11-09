namespace CipherSurface.Verification.Email;

/// <summary>
/// The sender used until a real email provider is registered. It never sends anything: asking it to send fails, so no
/// confirmation link can be issued without a provider. EmailVerificationService checks for this type first and refuses
/// the request before creating a challenge, and nothing is ever written to a log in its place (a logged link would be a
/// usable credential).
/// </summary>
public sealed class NotConfiguredEmailSender : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken ct) =>
        throw new InvalidOperationException("No email provider is configured.");
}
