using CipherSurface.Data.Enums;

namespace CipherSurface.Verification;

/// <summary>Maps a method to its verifier. Only observable methods can be registered.</summary>
public sealed class VerifierRegistry
{
    private readonly Dictionary<VerificationMethod, IOwnershipVerifier> _verifiers = new();

    public VerifierRegistry(IEnumerable<IOwnershipVerifier> verifiers)
    {
        ArgumentNullException.ThrowIfNull(verifiers);
        foreach (var verifier in verifiers)
        {
            if (!MethodTraits.IsObservable(verifier.Method))
                throw new ArgumentException($"{verifier.Method} is not observable and cannot have an IOwnershipVerifier.", nameof(verifiers));
            if (!_verifiers.TryAdd(verifier.Method, verifier))
                throw new ArgumentException($"Duplicate verifier for {verifier.Method}.", nameof(verifiers));
        }
    }

    public bool TryGet(VerificationMethod method, out IOwnershipVerifier verifier)
    {
        if (_verifiers.TryGetValue(method, out var found))
        {
            verifier = found;
            return true;
        }
        verifier = null!;
        return false;
    }
}
