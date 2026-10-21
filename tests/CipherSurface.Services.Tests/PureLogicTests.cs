using CipherSurface.Data.Enums;
using Xunit;

namespace CipherSurface.Services.Tests;

public class DomainStatusCalculatorTests
{
    private static DomainStatus Compute(DomainStatus current, bool dispute, params EvidenceStatus[] evidence) =>
        DomainStatusCalculator.Compute(current, evidence, dispute);

    [Fact]
    public void Revoked_Wins_OverEverything() =>
        Assert.Equal(DomainStatus.Revoked, Compute(DomainStatus.Revoked, true, EvidenceStatus.Active));

    [Fact]
    public void OpenDispute_Beats_ActiveEvidence() =>
        Assert.Equal(DomainStatus.Disputed, Compute(DomainStatus.Pending, true, EvidenceStatus.Active));

    [Fact]
    public void AnyActiveEvidence_IsVerified()
    {
        Assert.Equal(DomainStatus.Verified, Compute(DomainStatus.Pending, false, EvidenceStatus.Active));
        Assert.Equal(DomainStatus.Verified, Compute(DomainStatus.AtRisk, false, EvidenceStatus.Active, EvidenceStatus.AtRisk));
        Assert.Equal(DomainStatus.Verified, Compute(DomainStatus.Lapsed, false, EvidenceStatus.Lapsed, EvidenceStatus.Active));
    }

    [Fact]
    public void NoActive_ButAtRisk_IsAtRisk()
    {
        Assert.Equal(DomainStatus.AtRisk, Compute(DomainStatus.Verified, false, EvidenceStatus.AtRisk));
        Assert.Equal(DomainStatus.AtRisk, Compute(DomainStatus.Verified, false, EvidenceStatus.AtRisk, EvidenceStatus.Lapsed));
    }

    [Fact]
    public void OnlyDeadEvidence_IsLapsed() =>
        Assert.Equal(DomainStatus.Lapsed,
            Compute(DomainStatus.Verified, false, EvidenceStatus.Lapsed, EvidenceStatus.Expired, EvidenceStatus.Revoked));

    [Fact]
    public void NoEvidence_KeepsPendingOrFailed_AndNeverClaimsVerified()
    {
        Assert.Equal(DomainStatus.Pending, Compute(DomainStatus.Pending, false));
        Assert.Equal(DomainStatus.Failed, Compute(DomainStatus.Failed, false));
        Assert.Equal(DomainStatus.Pending, Compute(DomainStatus.Verified, false));
        Assert.Equal(DomainStatus.Pending, Compute(DomainStatus.Disputed, false)); // dispute closed, nothing proven
    }

    [Fact]
    public void ClosedDispute_FallsBackToTheEvidence() =>
        Assert.Equal(DomainStatus.Verified, Compute(DomainStatus.Disputed, false, EvidenceStatus.Active));
}

public class DomainNameValidatorTests
{
    private readonly DomainNameValidator _validator = new();

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  Example.COM.  ", "example.com")]
    [InlineData("shop.brightcart.com", "shop.brightcart.com")]
    [InlineData("münchen.de", "xn--mnchen-3ya.de")]
    public void ValidNames_AreNormalized(string input, string expected) =>
        Assert.Equal(expected, _validator.Normalize(input));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("http://example.com")]
    [InlineData("example.com/path")]
    [InlineData("user@example.com")]
    [InlineData("example")]
    [InlineData("192.168.1.1")]
    [InlineData("exa mple.com")]
    [InlineData("*.example.com")]
    [InlineData("example.com:8080")]
    [InlineData("a..example.com")]
    [InlineData("app.localhost")]
    [InlineData("printer.local")]
    [InlineData("db.internal")]
    public void InvalidNames_AreRejected(string? input)
    {
        var ex = Assert.Throws<ServiceException>(() => _validator.Normalize(input));
        Assert.Equal("DomainInvalid", ex.Code);
    }

    [Theory]
    [InlineData("co.uk")]
    [InlineData("github.io")]
    [InlineData("com.pk")]
    public void PublicSuffixes_AreRejected(string input)
    {
        var ex = Assert.Throws<ServiceException>(() => _validator.Normalize(input));
        Assert.Equal("DomainIsPublicSuffix", ex.Code);
    }

    [Fact]
    public void ADomainUnderAPublicSuffix_IsAllowed() =>
        Assert.Equal("mycompany.co.uk", _validator.Normalize("mycompany.co.uk"));
}
