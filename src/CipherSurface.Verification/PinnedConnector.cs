using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace CipherSurface.Verification;

public interface IHostResolver
{
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct);
}

public sealed class SystemHostResolver : IHostResolver
{
    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct) =>
        await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
}

public sealed class BlockedDestinationException : Exception
{
    public BlockedDestinationException(string message) : base(message) { }
}

/// <summary>
/// DNS-rebinding defence. This is plugged into SocketsHttpHandler.ConnectCallback, so it is the
/// ONLY place a connection is made. It resolves the name exactly once, validates every returned
/// address, then connects to one of those validated addresses. The HTTP stack never resolves the
/// name again, and still uses the original hostname for the Host header and TLS (SNI/certificate).
/// </summary>
public sealed class PinnedConnector
{
    public delegate Task<Stream> ConnectFunc(IPAddress address, int port, CancellationToken ct);

    private readonly IHostResolver _resolver;
    private readonly Func<IPAddress, bool> _isAllowed;
    private readonly HashSet<int> _allowedPorts;
    private readonly ConnectFunc _connect;

    public PinnedConnector(
        IHostResolver? resolver = null,
        Func<IPAddress, bool>? addressPolicy = null,
        IEnumerable<int>? allowedPorts = null,
        ConnectFunc? connect = null)
    {
        _resolver = resolver ?? new SystemHostResolver();
        _isAllowed = addressPolicy ?? SsrfGuard.IsPublicAddress;
        _allowedPorts = new HashSet<int>(allowedPorts ?? new[] { 80, 443 });
        _connect = connect ?? ConnectSocketAsync;
    }

    /// <summary>Signature required by SocketsHttpHandler.ConnectCallback.</summary>
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct) =>
        await ConnectToAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct).ConfigureAwait(false);

    public async Task<Stream> ConnectToAsync(string host, int port, CancellationToken ct)
    {
        if (!_allowedPorts.Contains(port))
            throw new BlockedDestinationException($"Port {port} is not allowed.");

        IReadOnlyList<IPAddress> addresses = IPAddress.TryParse(host, out var literal)
            ? new[] { literal }
            : await _resolver.ResolveAsync(host, ct).ConfigureAwait(false);

        if (addresses.Count == 0)
            throw new SocketException((int)SocketError.NoData);

        // Strict: if ANY answer is non-public, refuse. A mixed answer is a rebinding signal.
        if (addresses.Any(a => !_isAllowed(a)))
            throw new BlockedDestinationException("Host resolves to a non-public address.");

        Exception? last = null;
        foreach (var address in addresses)
        {
            try
            {
                return await _connect(address, port, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }

        throw last ?? new SocketException((int)SocketError.HostUnreachable);
    }

    private static async Task<Stream> ConnectSocketAsync(IPAddress address, int port, CancellationToken ct)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
