using CipherSurface.Data.Enums;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class DnsTxtVerifierTests
{
    private const string Token = "abcDEF0123456789_-xyz";
    private static readonly string Expected = "ciphersurface-verify=" + Token;

    private sealed class FakeDns : IDnsTxtResolver
    {
        private readonly DnsTxtLookup _lookup;
        public List<string> Queries { get; } = new();
        public FakeDns(DnsTxtStatus status, params string[] values) => _lookup = new DnsTxtLookup(status, values);
        public Task<DnsTxtLookup> LookupTxtAsync(string name, CancellationToken ct)
        {
            Queries.Add(name);
            return Task.FromResult(_lookup);
        }
    }

    private sealed class ThrowingDns : IDnsTxtResolver
    {
        public Task<DnsTxtLookup> LookupTxtAsync(string name, CancellationToken ct) => throw new InvalidOperationException("boom");
    }

    private static Task<VerificationObservation> Check(params IDnsTxtResolver[] resolvers) =>
        new DnsTxtVerifier(resolvers).CheckAsync(
            new VerificationRequest(VerificationMethod.DnsTxt, "example.com", Token), CancellationToken.None);

    [Fact]
    public async Task TokenPresent_IsValid()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, Expected));
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
    }

    [Fact]
    public async Task TokenAmongOtherTxtRecords_IsValid()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, "v=spf1 -all", Expected, "google-site-verification=zzz"));
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
    }

    [Fact]
    public async Task QueriesTheVerificationLabelUnderTheHost()
    {
        var dns = new FakeDns(DnsTxtStatus.Records, Expected);
        await Check(dns);
        Assert.Equal("_ciphersurface-verify.example.com", Assert.Single(dns.Queries));
    }

    [Fact]
    public async Task NxDomain_IsAbsent()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.NxDomain));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(Reasons.TxtRecordMissing, result.Reason);
    }

    [Fact]
    public async Task NoTxtRecords_IsAbsent()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.NoRecords));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task RecordsWithoutTheToken_IsAbsentWithMismatchReason()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, "ciphersurface-verify=someOtherTokenValue123"));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(Reasons.TokenMismatch, result.Reason);
    }

    [Fact]
    public async Task TokenAsSubstringOfAnotherValue_IsNotAccepted()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, Expected + "extra", "x" + Expected));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task OnlyFailures_IsInconclusive()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Failure), new FakeDns(DnsTxtStatus.Failure));
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
    }

    [Fact]
    public async Task OneResolverSeesToken_OtherFails_IsValid()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, Expected), new FakeDns(DnsTxtStatus.Failure));
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
    }

    [Fact]
    public async Task OneResolverSeesToken_OtherIsStale_IsValid()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.Records, Expected), new FakeDns(DnsTxtStatus.NxDomain));
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
    }

    [Fact]
    public async Task OneAbsent_OneFailure_IsInconclusive()
    {
        var result = await Check(new FakeDns(DnsTxtStatus.NxDomain), new FakeDns(DnsTxtStatus.Failure));
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
    }

    [Fact]
    public async Task ResolverThatThrows_IsInconclusive()
    {
        var result = await Check(new ThrowingDns());
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal(Reasons.VerifierError, result.Reason);
    }

    [Theory]
    [InlineData("93.184.216.34", Token)]   // IP literal
    [InlineData("Example.com", Token)]     // not normalized
    [InlineData("localhost", Token)]       // single label
    [InlineData("example.com", "short")]   // weak token
    [InlineData("example.com", "has space in token 123")]
    public async Task InvalidRequest_IsInconclusive_AndNoQueryIsMade(string host, string token)
    {
        var dns = new FakeDns(DnsTxtStatus.Records, Expected);
        var result = await new DnsTxtVerifier(new[] { dns }).CheckAsync(
            new VerificationRequest(VerificationMethod.DnsTxt, host, token), CancellationToken.None);

        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal(Reasons.InvalidRequest, result.Reason);
        Assert.Empty(dns.Queries);
    }

    [Fact]
    public async Task WrongMethodInRequest_IsInconclusive()
    {
        var result = await new DnsTxtVerifier(new[] { new FakeDns(DnsTxtStatus.Records, Expected) }).CheckAsync(
            new VerificationRequest(VerificationMethod.HttpFile, "example.com", Token), CancellationToken.None);
        Assert.Equal(Reasons.InvalidRequest, result.Reason);
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var verifier = new DnsTxtVerifier(new IDnsTxtResolver[] { new CancellingDns() });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            verifier.CheckAsync(new VerificationRequest(VerificationMethod.DnsTxt, "example.com", Token), cts.Token));
    }

    private sealed class CancellingDns : IDnsTxtResolver
    {
        public Task<DnsTxtLookup> LookupTxtAsync(string name, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new DnsTxtLookup(DnsTxtStatus.NoRecords, Array.Empty<string>()));
        }
    }
}
