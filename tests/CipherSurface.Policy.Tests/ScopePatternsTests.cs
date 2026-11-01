using Xunit;

namespace CipherSurface.Policy.Tests;

public sealed class ScopePatternsTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  WWW.Example.COM. ", "www.example.com")]
    [InlineData("*.example.com", "*.example.com")]
    [InlineData("*.EXAMPLE.com", "*.example.com")]
    [InlineData("a.b.example.com", "a.b.example.com")]
    [InlineData("b\u00fccher.example.com", "xn--bcher-kva.example.com")]
    public void Normalizes_AndAcceptsPatternsUnderTheDomain(string input, string expected)
    {
        Assert.True(ScopePatterns.TryNormalize(input, "example.com", out var normalized, out var error));
        Assert.Equal(expected, normalized);
        Assert.Null(error);
    }

    [Theory]
    [InlineData("other.com")]
    [InlineData("evilexample.com")]
    [InlineData("*.evilexample.com")]
    [InlineData("example.com.evil.com")]
    [InlineData("*.example.org")]
    public void RejectsPatternsOutsideTheDomain(string input)
    {
        Assert.False(ScopePatterns.TryNormalize(input, "example.com", out var normalized, out var error));
        Assert.Equal(ScopePatterns.OutsideDomain, error);
        Assert.Equal(string.Empty, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("*.*.example.com")]
    [InlineData("shop*.example.com")]
    [InlineData("https://shop.example.com")]
    [InlineData("shop.example.com:8443")]
    [InlineData("192.0.2.10")]
    [InlineData("shop..example.com")]
    [InlineData("example")]
    [InlineData("*.com")]
    public void RejectsMalformedPatterns(string? input)
    {
        Assert.False(ScopePatterns.TryNormalize(input, "example.com", out _, out var error));
        Assert.NotNull(error);
        Assert.NotEqual(ScopePatterns.OutsideDomain, error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("localhost")]
    public void RejectsAnInvalidDomainName(string? domain)
    {
        Assert.False(ScopePatterns.TryNormalize("www.example.com", domain, out _, out var error));
        Assert.Equal("InvalidDomainName", error);
    }

    [Theory]
    [InlineData("a.example.com", "example.com")]
    [InlineData("*.example.com", "example.com")]
    [InlineData("example.com", "example.com")]
    public void AcceptedPatterns_AreAlwaysParsedByTheCalculator(string pattern, string domain)
    {
        // A pattern that passes TryNormalize must never make the calculator fail closed on the whole domain.
        Assert.True(ScopePatterns.TryNormalize(pattern, domain, out var normalized, out _));
        var rule = TestFixture.Rule(CipherSurface.Data.Enums.ScopeRuleType.Include, normalized);
        var evidence = TestFixture.DnsEvidence();
        var result = new ScopeCalculator().Calculate(
            TestFixture.DomainId, domain,
            [new UsableEvidence(evidence.Id, evidence.DomainId, evidence.Method, evidence.ScopeCeilingType, evidence.Host)],
            [rule]);
        Assert.True(result.Succeeded, result.ErrorCode);
    }
}
