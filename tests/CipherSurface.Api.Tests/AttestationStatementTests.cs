using System.Security.Cryptography;
using System.Text;
using CipherSurface.Services;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>
/// Keeps the statement and its version in step. Every stored authorization records the version the user accepted, so
/// editing the wording without a new version would let an old acceptance pass for the new text.
/// </summary>
public class AttestationStatementTests
{
    [Fact]
    public void TheTextAndItsVersionChangeTogether()
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AttestationStatement.Text))).ToLowerInvariant();

        // If this fails after an edit: change AttestationStatement.CurrentVersion, then put the new version and hash here.
        Assert.Equal(("2026-11-v2", "60e391a5ec74714f67f9d42fe8c03f3f13f9503469cd58bdc79054542bb9d331"), (AttestationStatement.CurrentVersion, hash));
    }

    [Fact]
    public void TheStatementSeparatesOwnershipChecksFromLaterMonitoring()
    {
        // Verification makes limited DNS and HTTP requests; the passive-only promise is about what happens afterwards.
        Assert.Contains("DNS queries and HTTP requests", AttestationStatement.Text);
        Assert.Contains("after the domain is verified", AttestationStatement.Text);
        Assert.Contains("revoke", AttestationStatement.Text);
    }
}
