namespace CipherSurface.Data;

/// <summary>The SQL rules EF cannot express (triggers). Embedded so tests can apply them.</summary>
public static class IntegrityScripts
{
    public static string Load()
    {
        var assembly = typeof(IntegrityScripts).Assembly;
        var name = assembly.GetManifestResourceNames()
            .Single(n => n.EndsWith("001_integrity.sql", StringComparison.OrdinalIgnoreCase));
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
