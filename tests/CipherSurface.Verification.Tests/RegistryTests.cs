using CipherSurface.Data.Enums;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class RegistryTests
{
    private sealed class StubVerifier : IOwnershipVerifier
    {
        public StubVerifier(VerificationMethod method) => Method = method;
        public VerificationMethod Method { get; }
        public Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct) =>
            Task.FromResult(VerificationObservation.Valid());
    }

    [Theory]
    [InlineData(VerificationMethod.DnsTxt, true)]
    [InlineData(VerificationMethod.HttpFile, true)]
    [InlineData(VerificationMethod.HtmlMeta, true)]
    [InlineData(VerificationMethod.AdminEmail, false)]
    public void OnlyDnsHttpAndMetaAreObservable(VerificationMethod method, bool expected) =>
        Assert.Equal(expected, MethodTraits.IsObservable(method));

    [Fact]
    public void ReturnsTheRegisteredVerifier()
    {
        var dns = new StubVerifier(VerificationMethod.DnsTxt);
        var registry = new VerifierRegistry(new[] { dns });

        Assert.True(registry.TryGet(VerificationMethod.DnsTxt, out var found));
        Assert.Same(dns, found);
        Assert.False(registry.TryGet(VerificationMethod.HttpFile, out _));
    }

    [Fact]
    public void EmailCannotBeRegistered_BecauseItHasNothingToObserve() =>
        Assert.Throws<ArgumentException>(() => new VerifierRegistry(new[] { new StubVerifier(VerificationMethod.AdminEmail) }));

    [Fact]
    public void DuplicateMethodIsRejected() =>
        Assert.Throws<ArgumentException>(() => new VerifierRegistry(new[]
        {
            new StubVerifier(VerificationMethod.DnsTxt),
            new StubVerifier(VerificationMethod.DnsTxt)
        }));
}
