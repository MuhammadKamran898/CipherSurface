using System.Net;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class SsrfGuardTests
{
    [Theory]
    [InlineData("93.184.216.34")]
    [InlineData("8.8.8.8")]
    [InlineData("172.32.0.1")]      // just outside 172.16/12
    [InlineData("172.15.255.255")]  // just below 172.16/12
    [InlineData("100.63.255.255")]  // just below CGNAT
    [InlineData("100.128.0.1")]     // just above CGNAT
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")]
    public void PublicAddresses_AreAllowed(string ip) =>
        Assert.True(SsrfGuard.IsPublicAddress(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]   // cloud metadata
    [InlineData("100.64.0.1")]        // CGNAT
    [InlineData("224.0.0.1")]         // multicast
    [InlineData("255.255.255.255")]
    [InlineData("192.0.2.1")]         // TEST-NET-1
    [InlineData("198.18.0.1")]        // benchmarking
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("ff02::1")]
    [InlineData("fec0::1")]
    [InlineData("::ffff:127.0.0.1")]        // IPv4-mapped loopback
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]  // IPv4-mapped metadata
    [InlineData("64:ff9b::7f00:1")]         // NAT64 wrapping 127.0.0.1
    [InlineData("2001:db8::1")]
    [InlineData("2002:7f00:1::")]           // 6to4 wrapping 127.0.0.1
    public void NonPublicAddresses_AreBlocked(string ip) =>
        Assert.False(SsrfGuard.IsPublicAddress(IPAddress.Parse(ip)));
}
