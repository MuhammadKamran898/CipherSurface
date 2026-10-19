using System.Net;
using System.Net.Sockets;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class PinnedConnectorTests
{
    private static readonly IPAddress Public = IPAddress.Parse("93.184.216.34");
    private static readonly IPAddress Public2 = IPAddress.Parse("93.184.216.35");
    private static readonly IPAddress Loopback = IPAddress.Parse("127.0.0.1");

    private sealed class FakeResolver : IHostResolver
    {
        private readonly Func<int, IReadOnlyList<IPAddress>> _answer;
        public int Calls { get; private set; }
        public FakeResolver(Func<int, IReadOnlyList<IPAddress>> answer) => _answer = answer;
        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(_answer(Calls));
        }
    }

    private sealed class Recorder
    {
        public List<(IPAddress Address, int Port)> Connections { get; } = new();
        public Task<Stream> Connect(IPAddress address, int port, CancellationToken ct)
        {
            Connections.Add((address, port));
            return Task.FromResult<Stream>(Stream.Null);
        }
    }

    [Fact]
    public async Task ResolvesOnce_AndConnectsToTheValidatedAddress()
    {
        var resolver = new FakeResolver(_ => new[] { Public });
        var rec = new Recorder();
        var connector = new PinnedConnector(resolver, connect: rec.Connect);

        await connector.ConnectToAsync("example.com", 443, CancellationToken.None);

        Assert.Equal(1, resolver.Calls);
        var connection = Assert.Single(rec.Connections);
        Assert.Equal(Public, connection.Address);
        Assert.Equal(443, connection.Port);
    }

    [Fact]
    public async Task DnsRebinding_SecondAnswerIsNeverUsed()
    {
        // The attacker answers with a public IP first and 127.0.0.1 on any later lookup.
        var resolver = new FakeResolver(call => call == 1 ? new[] { Public } : new[] { Loopback });
        var rec = new Recorder();
        var connector = new PinnedConnector(resolver, connect: rec.Connect);

        await connector.ConnectToAsync("rebind.example.com", 80, CancellationToken.None);

        Assert.Equal(1, resolver.Calls);                 // never resolved a second time
        Assert.Equal(Public, Assert.Single(rec.Connections).Address); // connected to the validated IP
    }

    [Fact]
    public async Task PrivateAnswer_IsBlocked_AndNothingIsConnected()
    {
        var rec = new Recorder();
        var connector = new PinnedConnector(new FakeResolver(_ => new[] { Loopback }), connect: rec.Connect);

        await Assert.ThrowsAsync<BlockedDestinationException>(() =>
            connector.ConnectToAsync("evil.example.com", 443, CancellationToken.None));
        Assert.Empty(rec.Connections);
    }

    [Fact]
    public async Task MixedPublicAndPrivateAnswer_IsBlocked()
    {
        var rec = new Recorder();
        var connector = new PinnedConnector(new FakeResolver(_ => new[] { Public, IPAddress.Parse("10.0.0.5") }), connect: rec.Connect);

        await Assert.ThrowsAsync<BlockedDestinationException>(() =>
            connector.ConnectToAsync("mixed.example.com", 443, CancellationToken.None));
        Assert.Empty(rec.Connections);
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task LiteralPrivateIpHost_IsBlocked(string literal)
    {
        var resolver = new FakeResolver(_ => new[] { Public });
        var connector = new PinnedConnector(resolver, connect: new Recorder().Connect);

        await Assert.ThrowsAsync<BlockedDestinationException>(() =>
            connector.ConnectToAsync(literal, 80, CancellationToken.None));
        Assert.Equal(0, resolver.Calls);
    }

    [Theory]
    [InlineData(8080)]
    [InlineData(22)]
    [InlineData(6379)]
    public async Task NonWebPorts_AreBlocked(int port)
    {
        var rec = new Recorder();
        var connector = new PinnedConnector(new FakeResolver(_ => new[] { Public }), connect: rec.Connect);

        await Assert.ThrowsAsync<BlockedDestinationException>(() =>
            connector.ConnectToAsync("example.com", port, CancellationToken.None));
        Assert.Empty(rec.Connections);
    }

    [Fact]
    public async Task EmptyAnswer_IsHostNotFound()
    {
        var connector = new PinnedConnector(new FakeResolver(_ => Array.Empty<IPAddress>()), connect: new Recorder().Connect);

        var ex = await Assert.ThrowsAsync<SocketException>(() =>
            connector.ConnectToAsync("nothing.example.com", 443, CancellationToken.None));
        Assert.Equal(SocketError.NoData, ex.SocketErrorCode);
    }

    [Fact]
    public async Task FirstAddressFails_FallsBackToNextValidatedAddress()
    {
        var attempts = new List<IPAddress>();
        Task<Stream> Connect(IPAddress address, int port, CancellationToken ct)
        {
            attempts.Add(address);
            if (address.Equals(Public)) throw new SocketException((int)SocketError.ConnectionRefused);
            return Task.FromResult<Stream>(Stream.Null);
        }
        var connector = new PinnedConnector(new FakeResolver(_ => new[] { Public, Public2 }), connect: Connect);

        await connector.ConnectToAsync("example.com", 443, CancellationToken.None);

        Assert.Equal(new[] { Public, Public2 }, attempts);
    }
}
