using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using CipherSurface.Data.Enums;
using CipherSurface.Services;
using CipherSurface.Services.Tests;
using CipherSurface.Verification;
using CipherSurface.Verification.Email;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>A verifier whose answer is scripted by call number. It never touches the network.</summary>
public sealed class ApiScriptedVerifier : IOwnershipVerifier
{
    private int _calls;

    public ApiScriptedVerifier(VerificationMethod method) => Method = method;

    public VerificationMethod Method { get; }
    public Func<int, VerificationObservation> Script { get; set; } = _ => VerificationObservation.Absent(Reasons.TxtRecordMissing);
    public int Calls => _calls;

    public Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct) =>
        Task.FromResult(Script(Interlocked.Increment(ref _calls) - 1));
}

/// <summary>A real-looking email sender that keeps what it was asked to send.</summary>
public sealed class ApiRecordingEmailSender : IEmailSender
{
    private readonly List<EmailMessage> _sent = [];

    public IReadOnlyList<EmailMessage> Sent { get { lock (_sent) return [.. _sent]; } }
    public bool FailNext { get; set; }

    public Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        if (FailNext)
        {
            FailNext = false;
            throw new InvalidOperationException("SMTP is down");
        }
        lock (_sent) _sent.Add(message);
        return Task.CompletedTask;
    }
}

/// <summary>The doubles one API host needs: scripted verifiers (no DNS, no HTTP), an email recorder, and no retry delay.</summary>
public sealed class DomainRig
{
    public ApiScriptedVerifier Dns { get; } = new(VerificationMethod.DnsTxt);
    public ApiScriptedVerifier Http { get; } = new(VerificationMethod.HttpFile);
    public ApiScriptedVerifier Meta { get; } = new(VerificationMethod.HtmlMeta);
    public ApiRecordingEmailSender Email { get; } = new();

    public const string ConfirmationPage = "https://app.example.com/verify-email";

    public Action<IServiceCollection> Configure(bool withEmailSender = true) => services =>
    {
        services.AddSingleton(new VerifierRegistry(new IOwnershipVerifier[] { Dns, Http, Meta }));
        services.AddSingleton(new VerificationOptions { RetryDelay = TimeSpan.Zero });
        if (withEmailSender) services.AddSingleton<IEmailSender>(Email);
    };

    public static IReadOnlyDictionary<string, string?> WithEmailPage() =>
        new Dictionary<string, string?> { ["CipherSurface:Verification:EmailConfirmationPage"] = ConfirmationPage };
}

public sealed record Org(ApiHost Host, DomainRig Rig, Tokens Owner, Guid OrganizationId, Guid OwnerId, string OwnerEmail);

public static class DomainKit
{
    public const string V1 = "/api/v1";

    /// <summary>A host with scripted verifiers and one organization whose owner is signed in.</summary>
    public static async Task<Org> StartAsync(
        PostgresFixture postgres, IReadOnlyDictionary<string, string?>? settings = null, bool withEmailSender = true, TimeProvider? time = null)
    {
        var rig = new DomainRig();
        var host = await ApiHost.StartAsync(postgres, settings, time: time, configureServices: rig.Configure(withEmailSender));
        var (ownerId, orgId, email) = await host.RegisterAsync("owner@acme.example", "Acme");
        return new Org(host, rig, await host.LoginAsync(email), orgId, ownerId, email);
    }

    /// <summary>Another organization on the same host, with its own owner (a different tenant).</summary>
    public static async Task<(Tokens Owner, Guid OrganizationId)> OtherOrgAsync(ApiHost host, string email = "owner@other.example", string name = "Other")
    {
        var (_, orgId, _) = await host.RegisterAsync(email, name);
        return (await host.LoginAsync(email), orgId);
    }

    /// <summary>A person who belongs to the organization with the given role. They have an organization of their own too, so the header is always sent.</summary>
    public static async Task<Tokens> MemberAsync(ApiHost host, Guid organizationId, string email, MembershipRole role)
    {
        var (userId, _, _) = await host.RegisterAsync(email, email + " org");
        await host.AddMembershipAsync(userId, organizationId, role);
        return await host.LoginAsync(email);
    }

    public static async Task<JsonElement> BodyAsync(HttpResponseMessage response, HttpStatusCode expected)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == expected, $"Expected {(int)expected} but got {(int)response.StatusCode}: {text}");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    public static Task<HttpResponseMessage> CreateDomainAsync(
        ApiHost host, string bearer, string name, Guid? org = null, bool? accepted = true, string? version = AttestationStatement.CurrentVersion) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/domains", new { name, attestationVersion = version, accepted }, bearer, org);

    public static async Task<Guid> AddDomainAsync(ApiHost host, string bearer, string name, Guid? org = null)
    {
        var body = await BodyAsync(await CreateDomainAsync(host, bearer, name, org), HttpStatusCode.Created);
        return body.GetProperty("id").GetGuid();
    }

    public static Task<HttpResponseMessage> IssueChallengeAsync(ApiHost host, string bearer, Guid domainId, string? method, string? host2 = null, Guid? org = null) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/domains/{domainId}/challenges", new { method, host = host2 }, bearer, org);

    public static async Task<Guid> IssueAsync(ApiHost host, string bearer, Guid domainId, string method = "DnsTxt", string? challengeHost = null, Guid? org = null)
    {
        var body = await BodyAsync(await IssueChallengeAsync(host, bearer, domainId, method, challengeHost, org), HttpStatusCode.Created);
        return body.GetProperty("challengeId").GetGuid();
    }

    public static Task<HttpResponseMessage> VerifyAsync(ApiHost host, string bearer, Guid challengeId, Guid? org = null) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/challenges/{challengeId}/verify", null, bearer, org);

    public static Task<HttpResponseMessage> IssueEmailAsync(ApiHost host, string bearer, Guid domainId, string? recipient, Guid? org = null) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/domains/{domainId}/email-challenges", new { recipient }, bearer, org);

    public static Task<HttpResponseMessage> PreviewEmailAsync(ApiHost host, string bearer, Guid challengeId, Guid? org = null) =>
        host.GetAsync($"{V1}/email-challenges/{challengeId}", bearer, org);

    public static Task<HttpResponseMessage> ConfirmEmailAsync(ApiHost host, string bearer, Guid challengeId, string? token, Guid? org = null) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/email-challenges/{challengeId}/confirm", new { token }, bearer, org);

    public static Task<HttpResponseMessage> DetailsAsync(ApiHost host, string bearer, Guid domainId, Guid? org = null) =>
        host.GetAsync($"{V1}/domains/{domainId}", bearer, org);

    /// <summary>Reads the challenge id and the one-time token out of the link in a recorded confirmation email.</summary>
    public static (Guid ChallengeId, string Token) ReadLink(EmailMessage message)
    {
        var match = Regex.Match(message.TextBody, @"#c=(?<id>[0-9a-fA-F-]{36})&t=(?<token>[A-Za-z0-9_\-]+)");
        Assert.True(match.Success, "The email contains no confirmation link.");
        return (Guid.Parse(match.Groups["id"].Value), match.Groups["token"].Value);
    }

    public static async Task SuspendAsync(ApiHost host, Guid organizationId)
    {
        await using var db = host.Database.CreateDbContext();
        await db.Organizations.Where(o => o.Id == organizationId)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, OrganizationStatus.Suspended));
    }
}
