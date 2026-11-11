using System.Net;
using System.Security.Cryptography;
using System.Text;
using CipherSurface.Data.Enums;
using CipherSurface.Services;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static CipherSurface.Api.Tests.DomainKit;

namespace CipherSurface.Api.Tests;

/// <summary>Domain creation, listing and details: who may do what, and that one organization never sees another's data.</summary>
[Collection("postgres")]
public class DomainEndpointTests
{
    private readonly PostgresFixture _postgres;
    public DomainEndpointTests(PostgresFixture postgres) => _postgres = postgres;

    // ------------------------------------------------------------------ attestation

    [Fact]
    public async Task TheAuthorizationStatementIsServedToSignedInUsersOnly()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;

        var body = await Check.JsonAsync(await host.GetAsync($"{V1}/attestation", org.Owner.Access));

        Assert.Equal(AttestationStatement.CurrentVersion, body.GetProperty("version").GetString());
        Assert.Equal(AttestationStatement.Text, body.GetProperty("text").GetString());
        await Check.ProblemAsync(await host.GetAsync($"{V1}/attestation"), HttpStatusCode.Unauthorized, "Unauthorized");
    }

    // ------------------------------------------------------------------ creating

    [Fact]
    public async Task AnOwnerAddsADomain_AndTheStoredHashIsOfTheServersText()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;

        var response = await CreateDomainAsync(host, org.Owner.Access, "  Example.COM. ");
        var body = await BodyAsync(response, HttpStatusCode.Created);
        var id = body.GetProperty("id").GetGuid();

        Assert.Equal($"/api/v1/domains/{id}", response.Headers.Location!.ToString());
        Assert.Equal("example.com", body.GetProperty("name").GetString());
        Assert.Equal("Pending", body.GetProperty("status").GetString());
        Assert.Equal(org.OwnerId, body.GetProperty("createdByUserId").GetGuid());
        Assert.Equal("Active", body.GetProperty("authorization").GetProperty("status").GetString());
        Assert.Equal(AttestationStatement.CurrentVersion, body.GetProperty("authorization").GetProperty("attestationVersion").GetString());
        Assert.Empty(body.GetProperty("evidence").EnumerateArray().ToList());
        Assert.Empty(body.GetProperty("openChallenges").EnumerateArray().ToList());
        Assert.False(body.GetProperty("emailVerificationAvailable").GetBoolean());   // no confirmation page configured

        await using var db = host.Database.CreateDbContext();
        var domain = await db.Domains.SingleAsync();
        Assert.Equal(org.OrganizationId, domain.OrganizationId);
        var grant = await db.AuthorizationGrants.SingleAsync();
        var expectedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AttestationStatement.Text))).ToLowerInvariant();
        Assert.Equal(expectedHash, grant.AttestationHash);
        Assert.Equal("127.0.0.1", grant.Ip);
        var actions = await db.AuditLogs.Select(a => a.Action).ToListAsync();
        Assert.Contains("domain.added", actions);
        Assert.Contains("grant.created", actions);
    }

    [Fact]
    public async Task TheStatementMustBeAcceptedAndCurrent()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var token = org.Owner.Access;

        await Check.ProblemAsync(await CreateDomainAsync(host, token, "example.com", accepted: false), HttpStatusCode.BadRequest, "AttestationRequired");
        await Check.ProblemAsync(await CreateDomainAsync(host, token, "example.com", accepted: null), HttpStatusCode.BadRequest, "AttestationRequired");
        await Check.ProblemAsync(await CreateDomainAsync(host, token, "example.com", version: "old-version"), HttpStatusCode.Conflict, "AttestationOutdated");
        await Check.ProblemAsync(await CreateDomainAsync(host, token, "example.com", version: null), HttpStatusCode.Conflict, "AttestationOutdated");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.Domains);
        Assert.Empty(db.AuthorizationGrants);
    }

    [Theory]
    [InlineData("10.0.0.1", "DomainInvalid")]
    [InlineData("localhost", "DomainInvalid")]
    [InlineData("intranet.test", "DomainInvalid")]
    [InlineData("https://example.com", "DomainInvalid")]
    [InlineData("", "DomainInvalid")]
    [InlineData("co.uk", "DomainIsPublicSuffix")]
    [InlineData("github.io", "DomainIsPublicSuffix")]
    public async Task ANameNobodyCanOwnIsRefused(string name, string code)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;

        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, name), HttpStatusCode.BadRequest, code);

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.Domains);
    }

    [Fact]
    public async Task TheSameDomainTwiceInOneOrganizationConflicts_ButAnotherOrganizationMayAddIt()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var other = await OtherOrgAsync(host);

        await AddDomainAsync(host, org.Owner.Access, "example.com");
        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "EXAMPLE.com"), HttpStatusCode.Conflict, "DomainExists");

        // Another organization is not told that the name is taken; adding is allowed, and ownership is decided by proof.
        var theirs = await BodyAsync(await CreateDomainAsync(host, other.Owner.Access, "example.com"), HttpStatusCode.Created);
        Assert.Equal("Pending", theirs.GetProperty("status").GetString());

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(2, await db.Domains.CountAsync());
    }

    [Fact]
    public async Task OnlyOwnersAndAdminsAdd_AndTheRoleIsCheckedBeforeTheContent()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);
        var analyst = await MemberAsync(host, org.OrganizationId, "analyst@acme.example", MembershipRole.Analyst);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        Assert.Equal(HttpStatusCode.Created, (await CreateDomainAsync(host, admin.Access, "admin-added.example.com", org.OrganizationId)).StatusCode);

        // The name and the statement are both invalid, yet the answer is "not allowed": authorization comes first.
        foreach (var person in new[] { analyst, viewer })
            await Check.ProblemAsync(await CreateDomainAsync(host, person.Access, "10.0.0.1", org.OrganizationId, accepted: false, version: "x"), HttpStatusCode.Forbidden, "NotAllowed");

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, $"{V1}/domains", new { name = "example.com", attestationVersion = AttestationStatement.CurrentVersion, accepted = true }),
            HttpStatusCode.Unauthorized, "Unauthorized");

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(1, await db.Domains.CountAsync());
    }

    [Fact]
    public async Task ASuspendedOrganizationCannotAddDomains_ButCanStillReadThem()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var id = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await SuspendAsync(host, org.OrganizationId);

        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "second.example.com"), HttpStatusCode.Forbidden, "OrganizationSuspended");
        Assert.Equal(HttpStatusCode.OK, (await DetailsAsync(host, org.Owner.Access, id)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync($"{V1}/domains", org.Owner.Access)).StatusCode);
    }

    // ------------------------------------------------------------------ listing

    [Fact]
    public async Task TheListShowsOnlyTheCallersOrganization_ToEveryRole()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var other = await OtherOrgAsync(host);
        await AddDomainAsync(host, org.Owner.Access, "b.example.com");
        await AddDomainAsync(host, org.Owner.Access, "a.example.com");
        await AddDomainAsync(host, other.Owner.Access, "secret-of-the-other-org.example.com");
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        foreach (var person in new[] { org.Owner, viewer })
        {
            var response = await host.GetAsync($"{V1}/domains", person.Access, org.OrganizationId);
            var text = await response.Content.ReadAsStringAsync();
            var body = await Check.JsonAsync(response);

            Assert.Equal(2, body.GetProperty("total").GetInt32());
            Assert.Equal(new[] { "a.example.com", "b.example.com" }, body.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("name").GetString()).ToArray());
            Assert.DoesNotContain("secret-of-the-other-org", text);
            Assert.DoesNotContain(other.OrganizationId.ToString(), text);
        }

        var theirs = await Check.JsonAsync(await host.GetAsync($"{V1}/domains", other.Owner.Access));
        Assert.Equal(1, theirs.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task TheListIsPagedInAStableOrder()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        foreach (var n in new[] { 3, 1, 5, 2, 4 }) await AddDomainAsync(host, org.Owner.Access, $"d{n}.example.com");

        var second = await Check.JsonAsync(await host.GetAsync($"{V1}/domains?page=2&pageSize=2", org.Owner.Access));
        Assert.Equal(new[] { "d3.example.com", "d4.example.com" }, second.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("name").GetString()).ToArray());
        Assert.Equal(5, second.GetProperty("total").GetInt32());
        Assert.Equal(2, second.GetProperty("page").GetInt32());
        Assert.Equal(2, second.GetProperty("pageSize").GetInt32());

        var last = await Check.JsonAsync(await host.GetAsync($"{V1}/domains?page=3&pageSize=2", org.Owner.Access));
        last.GetProperty("items").EnumerateArray().Single();

        var beyond = await Check.JsonAsync(await host.GetAsync($"{V1}/domains?page=9&pageSize=2", org.Owner.Access));
        Assert.Empty(beyond.GetProperty("items").EnumerateArray().ToList());
        Assert.Equal(5, beyond.GetProperty("total").GetInt32());
    }

    [Theory]
    [InlineData("page=0")]
    [InlineData("page=-1")]
    [InlineData("page=abc")]
    [InlineData("pageSize=0")]
    [InlineData("pageSize=201")]
    [InlineData("status=Bogus")]
    [InlineData("status=1")]
    public async Task BadPagingOrFilterIsRefused(string query)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;

        await Check.ProblemAsync(await host.GetAsync($"{V1}/domains?{query}", org.Owner.Access), HttpStatusCode.BadRequest, "InvalidRequest");
    }

    [Fact]
    public async Task TheListCanBeFilteredByStatus_AndShowsLiveEvidence()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var verified = await AddDomainAsync(host, org.Owner.Access, "verified.example.com");
        await AddDomainAsync(host, org.Owner.Access, "pending.example.com");
        var challenge = await IssueAsync(host, org.Owner.Access, verified);
        org.Rig.Dns.Script = _ => CipherSurface.Verification.VerificationObservation.Valid();
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(host, org.Owner.Access, challenge)).StatusCode);

        var onlyVerified = await Check.JsonAsync(await host.GetAsync($"{V1}/domains?status=verified", org.Owner.Access));   // any letter case
        var item = onlyVerified.GetProperty("items").EnumerateArray().Single();
        Assert.Equal("verified.example.com", item.GetProperty("name").GetString());
        var evidence = item.GetProperty("evidence").EnumerateArray().Single();
        Assert.Equal("DnsTxt", evidence.GetProperty("method").GetString());
        Assert.Equal("Active", evidence.GetProperty("status").GetString());

        var onlyPending = await Check.JsonAsync(await host.GetAsync($"{V1}/domains?status=Pending", org.Owner.Access));
        Assert.Equal("pending.example.com", onlyPending.GetProperty("items").EnumerateArray().Single().GetProperty("name").GetString());
        Assert.Empty((await Check.JsonAsync(await host.GetAsync($"{V1}/domains?status=Lapsed", org.Owner.Access))).GetProperty("items").EnumerateArray().ToList());
    }

    [Fact]
    public async Task AUserInSeveralOrganizationsMustChoose_AndTheHeaderOnlyChoosesAmongTheirOwn()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var other = await OtherOrgAsync(host);
        await host.AddMembershipAsync(org.OwnerId, other.OrganizationId, MembershipRole.Viewer);
        await AddDomainAsync(host, org.Owner.Access, "mine.example.com", org.OrganizationId);
        await AddDomainAsync(host, other.Owner.Access, "theirs.example.com");

        await Check.ProblemAsync(await host.GetAsync($"{V1}/domains", org.Owner.Access), HttpStatusCode.BadRequest, "OrganizationRequired");

        var mine = await Check.JsonAsync(await host.GetAsync($"{V1}/domains", org.Owner.Access, org.OrganizationId));
        Assert.Equal("mine.example.com", mine.GetProperty("items").EnumerateArray().Single().GetProperty("name").GetString());
        var asViewer = await Check.JsonAsync(await host.GetAsync($"{V1}/domains", org.Owner.Access, other.OrganizationId));
        Assert.Equal("theirs.example.com", asViewer.GetProperty("items").EnumerateArray().Single().GetProperty("name").GetString());

        // In the other organization this person is only a Viewer: reading works, writing does not.
        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "new.example.com", other.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
    }

    // ------------------------------------------------------------------ details

    [Fact]
    public async Task ADomainOfAnotherOrganization_IsNotFound_LikeOneThatDoesNotExist()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var other = await OtherOrgAsync(host);
        var theirs = await AddDomainAsync(host, other.Owner.Access, "theirs.example.com");

        var crossTenant = await Check.ProblemAsync(await DetailsAsync(host, org.Owner.Access, theirs), HttpStatusCode.NotFound, "NotFound");
        var missing = await Check.ProblemAsync(await DetailsAsync(host, org.Owner.Access, Guid.NewGuid()), HttpStatusCode.NotFound, "NotFound");

        Assert.Equal(missing.GetProperty("detail").GetString(), crossTenant.GetProperty("detail").GetString());
        await Check.ProblemAsync(await host.GetAsync($"{V1}/domains/not-a-guid", org.Owner.Access), HttpStatusCode.NotFound, "NotFound");
    }

    [Fact]
    public async Task DetailsShowTheInstructionToManagersOnly()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var id = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var issued = await BodyAsync(await IssueChallengeAsync(host, org.Owner.Access, id, "DnsTxt"), HttpStatusCode.Created);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);
        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);

        var asOwner = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, id));
        var asAdmin = await Check.JsonAsync(await DetailsAsync(host, admin.Access, id, org.OrganizationId));
        var viewerResponse = await DetailsAsync(host, viewer.Access, id, org.OrganizationId);
        var viewerText = await viewerResponse.Content.ReadAsStringAsync();
        var asViewer = await Check.JsonAsync(viewerResponse);

        var instruction = issued.GetProperty("instruction").GetString();
        Assert.Equal(instruction, asOwner.GetProperty("openChallenges").EnumerateArray().Single().GetProperty("instruction").GetString());
        Assert.Equal(instruction, asAdmin.GetProperty("openChallenges").EnumerateArray().Single().GetProperty("instruction").GetString());

        var seenByViewer = asViewer.GetProperty("openChallenges").EnumerateArray().Single();
        Assert.Equal(System.Text.Json.JsonValueKind.Null, seenByViewer.GetProperty("instruction").ValueKind);
        Assert.Equal("DnsTxt", seenByViewer.GetProperty("method").GetString());
        Assert.DoesNotContain("ciphersurface-verify=", viewerText);
    }

    [Fact]
    public async Task EveryNewEndpointRequiresALogin()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var id = Guid.NewGuid();

        var calls = new (HttpMethod Method, string Path)[]
        {
            (HttpMethod.Get, $"{V1}/domains"),
            (HttpMethod.Post, $"{V1}/domains"),
            (HttpMethod.Get, $"{V1}/domains/{id}"),
            (HttpMethod.Post, $"{V1}/domains/{id}/challenges"),
            (HttpMethod.Post, $"{V1}/domains/{id}/email-challenges"),
            (HttpMethod.Post, $"{V1}/challenges/{id}/verify"),
            (HttpMethod.Get, $"{V1}/email-challenges/{id}"),
            (HttpMethod.Post, $"{V1}/email-challenges/{id}/confirm")
        };
        foreach (var (method, path) in calls)
            await Check.ProblemAsync(await host.SendAsync(method, path), HttpStatusCode.Unauthorized, "Unauthorized");
    }
}
