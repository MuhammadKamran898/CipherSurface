using System.Net;
using System.Net.Sockets;

namespace CipherSurface.Verification;

/// <summary>Decides whether an IP address is a public, routable internet address.</summary>
public static class SsrfGuard
{
    public static bool IsPublicAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsPublicV4(address.GetAddressBytes()),
            AddressFamily.InterNetworkV6 => IsPublicV6(address),
            _ => false
        };
    }

    private static bool IsPublicV4(byte[] b)
    {
        if (b[0] == 0) return false;                                   // 0.0.0.0/8
        if (b[0] == 10) return false;                                  // 10.0.0.0/8
        if (b[0] == 100 && (b[1] & 0xC0) == 64) return false;          // 100.64.0.0/10 CGNAT
        if (b[0] == 127) return false;                                 // loopback
        if (b[0] == 169 && b[1] == 254) return false;                  // link-local incl. cloud metadata
        if (b[0] == 172 && (b[1] & 0xF0) == 16) return false;          // 172.16.0.0/12
        if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;       // 192.0.0.0/24
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;       // TEST-NET-1
        if (b[0] == 192 && b[1] == 88 && b[2] == 99) return false;     // 6to4 relay
        if (b[0] == 192 && b[1] == 168) return false;                  // 192.168.0.0/16
        if (b[0] == 198 && (b[1] & 0xFE) == 18) return false;          // 198.18.0.0/15 benchmarking
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;    // TEST-NET-2
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;     // TEST-NET-3
        if (b[0] >= 224) return false;                                 // multicast, reserved, broadcast
        return true;
    }

    private static bool IsPublicV6(IPAddress a)
    {
        if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || a.IsIPv6UniqueLocal)
            return false;

        var b = a.GetAddressBytes();
        // Only global unicast 2000::/3 is allowed. That excludes ::/8 (unspecified, loopback,
        // IPv4-compatible) and the NAT64 prefix 64:ff9b::/96.
        if ((b[0] & 0xE0) != 0x20) return false;
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false; // 2001:db8::/32 documentation
        if (b[0] == 0x20 && b[1] == 0x02) return false;                                  // 2002::/16 6to4
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return false;  // 2001::/32 Teredo
        return true;
    }
}
