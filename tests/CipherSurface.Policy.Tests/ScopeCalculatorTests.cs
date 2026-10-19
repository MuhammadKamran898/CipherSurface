using CipherSurface.Data.Enums;
using Xunit;

namespace CipherSurface.Policy.Tests;

public sealed class ScopeCalculatorTests
{
    private readonly ScopeCalculator _calculator = new();

    [Fact]
    public void DnsCeiling_CoversRootAndSubdomainsAtAnyDepth()
    {
        var dns = TestFixture.DnsEvidence();
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(dns.Id, dns.DomainId, dns.Method, dns.ScopeCeilingType, dns.Host)],
            [TestFixture.Rule(ScopeRuleType.Include, "example.com"), TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]);

        Assert.True(result.Succeeded);
        Assert.True(result.Scope!.ContainsHost("example.com"));
        Assert.True(result.Scope.ContainsHost("a.example.com"));
        Assert.True(result.Scope.ContainsHost("a.b.example.com"));
        Assert.False(result.Scope.ContainsHost("notexample.com"));
        Assert.False(result.Scope.ContainsHost("example.net"));
    }

    [Fact]
    public void ExactHostCeiling_DoesNotCoverSiblingOrParent()
    {
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(meta.Id, meta.DomainId, meta.Method, meta.ScopeCeilingType, meta.Host)],
            [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]);

        Assert.True(result.Succeeded);
        Assert.True(result.Scope!.ContainsHost("www.example.com"));
        Assert.False(result.Scope.ContainsHost("api.example.com"));
        Assert.False(result.Scope.ContainsHost("example.com"));
    }

    [Fact]
    public void ExclusionsAlwaysWinOverBroadIncludes()
    {
        var dns = TestFixture.DnsEvidence();
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(dns.Id, dns.DomainId, dns.Method, dns.ScopeCeilingType, dns.Host)],
            [TestFixture.Rule(ScopeRuleType.Include, "*.example.com"), TestFixture.Rule(ScopeRuleType.Exclude, "admin.example.com")]);

        Assert.True(result.Succeeded);
        Assert.True(result.Scope!.ContainsHost("app.example.com"));
        Assert.False(result.Scope.ContainsHost("admin.example.com"));
        Assert.False(result.Scope.ContainsHost("deep.admin.example.com"));
    }

    [Fact]
    public void WildcardIntersection_ProducesNarrowerWildcard()
    {
        var dns = TestFixture.DnsEvidence();
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(dns.Id, dns.DomainId, dns.Method, dns.ScopeCeilingType, dns.Host)],
            [TestFixture.Rule(ScopeRuleType.Include, "*.shop.example.com")]);

        Assert.True(result.Succeeded);
        Assert.False(result.Scope!.ContainsHost("shop.example.com")); // Wildcards do not include their apex.
        Assert.True(result.Scope.ContainsHost("a.shop.example.com"));
        Assert.True(result.Scope.ContainsHost("a.b.shop.example.com"));
        Assert.False(result.Scope.ContainsHost("api.example.com"));
    }

    [Fact]
    public void NoApprovedIncludes_ProducesEmptyScope()
    {
        var dns = TestFixture.DnsEvidence();
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(dns.Id, dns.DomainId, dns.Method, dns.ScopeCeilingType, dns.Host)],
            [TestFixture.Rule(ScopeRuleType.Exclude, "admin.example.com")]);

        Assert.True(result.Succeeded);
        Assert.True(result.Scope!.IsEmpty);
        Assert.False(result.Scope.ContainsHost("app.example.com"));
    }

    [Fact]
    public void WildcardCeilingFromNonDnsEvidence_IsRejected()
    {
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(meta.Id, meta.DomainId, VerificationMethod.HtmlMeta, ScopeCeilingType.DomainAndSubdomains, meta.Host)],
            [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]);

        Assert.False(result.Succeeded);
        Assert.Equal("WildcardCeilingRequiresDns", result.ErrorCode);
    }

    [Fact]
    public void ScopeRuleOutsideDomain_IsRejectedFailClosed()
    {
        var dns = TestFixture.DnsEvidence();
        var foreignRule = TestFixture.Rule(ScopeRuleType.Include, "evil.example.net");
        var result = _calculator.Calculate(
            TestFixture.DomainId,
            "example.com",
            [new UsableEvidence(dns.Id, dns.DomainId, dns.Method, dns.ScopeCeilingType, dns.Host)],
            [foreignRule]);

        Assert.False(result.Succeeded);
        Assert.Equal("InvalidScopeRule", result.ErrorCode);
    }
}
