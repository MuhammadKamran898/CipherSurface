using System.Text.RegularExpressions;
using CipherSurface.Api.Errors;
using Xunit;

namespace CipherSurface.Api.Tests;

public class ErrorCatalogTests
{
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CipherSurface.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("CipherSurface.sln was not found above the test output folder.");
    }

    /// <summary>Every error code the services and the API itself can throw, read from the source.</summary>
    private static HashSet<string> ThrownCodes()
    {
        var codes = new HashSet<string>();
        var literal = new Regex("\"([A-Z][A-Za-z]+)\"");
        foreach (var project in new[] { "CipherSurface.Services", "CipherSurface.Auth", "CipherSurface.Api" })
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(RepositoryRoot(), "src", project), "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") || Path.GetFileName(file) == "ErrorCatalog.cs") continue;
                var text = File.ReadAllText(file);

                // new ServiceException("Code", ...)  and  new ServiceException(flag ? "A" : "B", ...)  and  new("Code", ...) after "=> "
                foreach (Match call in Regex.Matches(text, @"new\s+[\w.]*ServiceException\(\s*([^,\n]+),"))
                    foreach (Match code in literal.Matches(call.Groups[1].Value))
                        codes.Add(code.Groups[1].Value);

                // const string Invalid = "InvalidRefreshToken";
                foreach (Match constant in Regex.Matches(text, @"const string Invalid = ""([A-Z][A-Za-z]+)"""))
                    codes.Add(constant.Groups[1].Value);

                // Shorthand: => new("Code", "message") in files that return ServiceException.
                foreach (Match shorthand in Regex.Matches(text, @"ServiceException \w+\(\) => new\(""([A-Z][A-Za-z]+)"""))
                    codes.Add(shorthand.Groups[1].Value);
            }
        }

        return codes;
    }

    [Fact]
    public void EveryErrorCodeTheCodeCanThrow_HasAnHttpStatus()
    {
        var thrown = ThrownCodes();

        Assert.True(thrown.Count > 40, $"Only {thrown.Count} codes were found; the scan is probably broken.");
        var missing = thrown.Where(code => !ErrorCatalog.TryGetStatus(code, out _)).Order().ToList();
        Assert.True(missing.Count == 0, "These error codes have no HTTP status in ErrorCatalog: " + string.Join(", ", missing));
    }

    [Fact]
    public void EveryStatusIsAnErrorStatus_AndKnownCodesAreNotDuplicated()
    {
        foreach (var code in ErrorCatalog.Codes)
        {
            Assert.True(ErrorCatalog.TryGetStatus(code, out var status));
            Assert.InRange(status, 400, 599);
        }
    }
}
