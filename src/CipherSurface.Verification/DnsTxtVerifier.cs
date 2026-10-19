using System.Net;
using CipherSurface.Data.Enums;
using DnsClient;

namespace CipherSurface.Verification;

public enum DnsTxtStatus
{
    Records,    // the name has TXT records (the token may or may not be among them)
    NoRecords,  // the name exists but has no TXT records
    NxDomain,   // the name does not exist
    Failure     // timeout, SERVFAIL, refused, network error
}

public sealed record DnsTxtLookup(DnsTxtStatus Status, IReadOnlyList<string> Values);

public interface IDnsTxtResolver
{
    Task<DnsTxtLookup> LookupTxtAsync(string name, CancellationToken ct);
}

/// <summary>One public resolver, queried directly with caching disabled so removals are noticed.</summary>
public sealed class DnsClientTxtResolver : IDnsTxtResolver
{
    private readonly ILookupClient _client;

    public DnsClientTxtResolver(IPAddress server, TimeSpan? timeout = null)
    {
        _client = new LookupClient(new LookupClientOptions(server)
        {
            UseCache = false,
            Timeout = timeout ?? TimeSpan.FromSeconds(5),
            Retries = 1,
            ThrowDnsErrors = false,
            UseTcpFallback = true
        });
    }

    public async Task<DnsTxtLookup> LookupTxtAsync(string name, CancellationToken ct)
    {
        try
        {
            var response = await _client.QueryAsync(name, QueryType.TXT, QueryClass.IN, ct).ConfigureAwait(false);
            var code = response.Header.ResponseCode.ToString();
            if (code == "NotExistentDomain") return new DnsTxtLookup(DnsTxtStatus.NxDomain, Array.Empty<string>());
            if (code != "NoError") return new DnsTxtLookup(DnsTxtStatus.Failure, Array.Empty<string>());

            // A TXT record may be split into several strings; join them back together.
            var values = response.Answers.TxtRecords().Select(r => string.Concat(r.Text)).ToArray();
            return values.Length == 0
                ? new DnsTxtLookup(DnsTxtStatus.NoRecords, Array.Empty<string>())
                : new DnsTxtLookup(DnsTxtStatus.Records, values);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new DnsTxtLookup(DnsTxtStatus.Failure, Array.Empty<string>());
        }
    }
}

/// <summary>
/// Looks for TXT "ciphersurface-verify=TOKEN" at _ciphersurface-verify.HOST on several resolvers.
/// Combining rule: any resolver that sees the token wins (a stale or lagging resolver must not
/// block a fresh proof). Otherwise ProofAbsent only if every resolver answered; if any resolver
/// failed and none saw the token, the result is Inconclusive.
/// </summary>
public sealed class DnsTxtVerifier : IOwnershipVerifier
{
    private readonly IReadOnlyList<IDnsTxtResolver> _resolvers;

    public DnsTxtVerifier(IReadOnlyList<IDnsTxtResolver> resolvers)
    {
        ArgumentNullException.ThrowIfNull(resolvers);
        if (resolvers.Count == 0) throw new ArgumentException("At least one resolver is required.", nameof(resolvers));
        _resolvers = resolvers;
    }

    public VerificationMethod Method => VerificationMethod.DnsTxt;

    public async Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Method != VerificationMethod.DnsTxt ||
            !ProofFormat.IsValidHost(request.Host) ||
            !ProofFormat.IsValidToken(request.Token))
            return VerificationObservation.Inconclusive(Reasons.InvalidRequest);

        var name = $"{ProofFormat.DnsLabel}.{request.Host}";
        var expected = ProofFormat.ExpectedValue(request.Token);

        DnsTxtLookup[] lookups;
        try
        {
            lookups = await Task.WhenAll(_resolvers.Select(r => r.LookupTxtAsync(name, ct))).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return VerificationObservation.Inconclusive(Reasons.VerifierError);
        }

        var anyValid = false;
        var anyFailure = false;
        var anyMismatch = false;
        foreach (var lookup in lookups)
        {
            switch (lookup.Status)
            {
                case DnsTxtStatus.Records:
                    if (lookup.Values.Any(v => string.Equals(v.Trim(), expected, StringComparison.Ordinal)))
                        anyValid = true;
                    else
                        anyMismatch = true;
                    break;
                case DnsTxtStatus.NoRecords:
                case DnsTxtStatus.NxDomain:
                    break; // a definite "not there"
                default:
                    anyFailure = true;
                    break;
            }
        }

        if (anyValid) return VerificationObservation.Valid();
        if (anyFailure) return VerificationObservation.Inconclusive(Reasons.ResolverFailure);
        return VerificationObservation.Absent(anyMismatch ? Reasons.TokenMismatch : Reasons.TxtRecordMissing);
    }
}
