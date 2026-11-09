using System.Globalization;
using CipherSurface.Verification.Email;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// The Public Suffix List algorithm, checked against a small list written in the real file format. The expected answers
/// follow the format specification (exception rules prevail, then the rule with most labels, otherwise "*"), including
/// the well-known example families (jp, kobe, ak.us, ck).
/// </summary>
public class PublicSuffixListTests
{
    private const string Fixture = """
        // This is a comment, and blank lines are ignored.

        // ===BEGIN ICANN DOMAINS===
        com
        biz
        jp
        ac.jp
        kyoto.jp
        ide.kyoto.jp
        *.kobe.jp
        !city.kobe.jp
        us
        ak.us
        k12.ak.us
        uk
        co.uk
        *.ck
        !www.ck
        cn
        com.cn
        公司.cn
        中国
        // ===BEGIN PRIVATE DOMAINS===
        github.io     trailing text after whitespace is ignored
        blogspot.com
        """;

    private static readonly PublicSuffixList List = PublicSuffixList.Parse(new StringReader(Fixture));

    private static string Ascii(string name) =>
        string.Join('.', name.Split('.').Select(l => l.All(char.IsAscii) ? l : new IdnMapping().GetAscii(l)));

    // ------------------------------------------------------------------ the algorithm

    [Theory]
    [InlineData("com", null)]
    [InlineData("example.com", "example.com")]
    [InlineData("b.example.com", "example.com")]
    [InlineData("a.b.example.com", "example.com")]
    [InlineData("biz", null)]
    [InlineData("domain.biz", "domain.biz")]
    [InlineData("b.domain.biz", "domain.biz")]
    [InlineData("jp", null)]
    [InlineData("test.jp", "test.jp")]
    [InlineData("www.test.jp", "test.jp")]
    [InlineData("ac.jp", null)]
    [InlineData("test.ac.jp", "test.ac.jp")]
    [InlineData("www.test.ac.jp", "test.ac.jp")]
    [InlineData("kyoto.jp", null)]
    [InlineData("test.kyoto.jp", "test.kyoto.jp")]
    [InlineData("ide.kyoto.jp", null)]
    [InlineData("b.ide.kyoto.jp", "b.ide.kyoto.jp")]
    [InlineData("a.b.ide.kyoto.jp", "b.ide.kyoto.jp")]
    [InlineData("c.kobe.jp", null)]                     // wildcard *.kobe.jp: c.kobe.jp is a suffix
    [InlineData("b.c.kobe.jp", "b.c.kobe.jp")]
    [InlineData("a.b.c.kobe.jp", "b.c.kobe.jp")]
    [InlineData("city.kobe.jp", "city.kobe.jp")]        // exception !city.kobe.jp
    [InlineData("www.city.kobe.jp", "city.kobe.jp")]
    [InlineData("us", null)]
    [InlineData("test.us", "test.us")]
    [InlineData("ak.us", null)]
    [InlineData("test.ak.us", "test.ak.us")]
    [InlineData("k12.ak.us", null)]
    [InlineData("test.k12.ak.us", "test.k12.ak.us")]
    [InlineData("www.test.k12.ak.us", "test.k12.ak.us")]
    [InlineData("foo.ck", null)]                        // wildcard *.ck
    [InlineData("bar.foo.ck", "bar.foo.ck")]
    [InlineData("www.ck", "www.ck")]                    // exception !www.ck
    [InlineData("a.www.ck", "www.ck")]
    [InlineData("shop.co.uk", "shop.co.uk")]
    [InlineData("co.uk", null)]
    [InlineData("example", null)]                       // no rule: the implicit "*" makes the last label the suffix
    [InlineData("example.example", "example.example")]
    [InlineData("a.b.example.example", "example.example")]
    public void TheRegistrableDomainFollowsTheAlgorithm(string name, string? expected) =>
        Assert.Equal(expected, List.GetRegistrableDomain(name));

    [Theory]
    [InlineData("食狮.com.cn", "食狮.com.cn")]
    [InlineData("www.食狮.com.cn", "食狮.com.cn")]
    [InlineData("食狮.公司.cn", "食狮.公司.cn")]
    [InlineData("www.食狮.公司.cn", "食狮.公司.cn")]
    [InlineData("公司.cn", null)]
    [InlineData("中国", null)]
    [InlineData("食狮.中国", "食狮.中国")]
    public void InternationalizedRulesAreMatchedInTheirAsciiForm(string name, string? expected) =>
        Assert.Equal(expected is null ? null : Ascii(expected), List.GetRegistrableDomain(Ascii(name)));

    [Theory]
    [InlineData("com", true)]
    [InlineData("co.uk", true)]
    [InlineData("github.io", true)]          // the private section counts
    [InlineData("blogspot.com", true)]
    [InlineData("foo.ck", true)]
    [InlineData("c.kobe.jp", true)]
    [InlineData("k12.ak.us", true)]
    [InlineData("example", true)]            // unlisted last label
    [InlineData("example.com", false)]
    [InlineData("www.github.io", false)]
    [InlineData("mysite.blogspot.com", false)]
    [InlineData("www.ck", false)]
    [InlineData("city.kobe.jp", false)]
    [InlineData("example.example", false)]
    public void ASuffixIsRecognized(string name, bool expected) =>
        Assert.Equal(expected, List.IsPublicSuffix(name));

    [Theory]
    [InlineData("WWW.Example.COM.", "com", "example.com")]
    [InlineData("  Shop.Co.UK  ", "co.uk", "shop.co.uk")]
    public void NamesAreComparedCaseInsensitively_WithoutATrailingDot(string name, string suffix, string registrable)
    {
        Assert.Equal(suffix, List.GetPublicSuffix(name));
        Assert.Equal(registrable, List.GetRegistrableDomain(name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".com")]
    [InlineData("a..com")]
    [InlineData(".")]
    public void AnInvalidNameIsNeverASuffix_AndHasNoRegistrableDomain(string? name)
    {
        Assert.False(List.IsPublicSuffix(name!));
        Assert.Null(List.GetPublicSuffix(name!));
        Assert.Null(List.GetRegistrableDomain(name!));
    }

    // ------------------------------------------------------------------ reading the file

    [Fact]
    public void CommentsBlankLinesAndTrailingTextAreIgnored_AndDuplicatesCountOnce()
    {
        var list = PublicSuffixList.Parse(new StringReader("// c\n\n  com  \nco.uk   # note\ncom\n*.ck\n!www.ck\n"));

        Assert.Equal(4, list.RuleCount);   // com, co.uk, *.ck, !www.ck
        Assert.True(list.IsPublicSuffix("co.uk"));
    }

    [Fact]
    public void AListWithoutRulesIsRefused()
    {
        Assert.Throws<FormatException>(() => PublicSuffixList.Parse(new StringReader("// only comments\n\n")));
    }

    [Theory]
    [InlineData("a..b")]
    [InlineData("!*.example")]
    [InlineData("*.")]
    [InlineData(".com")]
    public void ARuleThatCannotBeReadStopsTheLoad_WithTheLineNumber(string badRule)
    {
        var ex = Assert.Throws<FormatException>(() => PublicSuffixList.Parse(new StringReader($"com\n// fine\n{badRule}\nco.uk\n")));

        Assert.Contains("line 3", ex.Message);
    }

    [Fact]
    public void ALoadedFile_BehavesLikeTheParsedText()
    {
        var path = Path.Combine(Path.GetTempPath(), "psl-" + Guid.NewGuid().ToString("N") + ".dat");
        File.WriteAllText(path, Fixture);
        try
        {
            Assert.True(PublicSuffixList.LoadFile(path).IsPublicSuffix("github.io"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void AMissingFileIsAnIoError()
    {
        Assert.ThrowsAny<IOException>(() => PublicSuffixList.LoadFile(Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid().ToString("N"))));
    }

    // ------------------------------------------------------------------ the validator that uses it

    [Theory]
    [InlineData("github.io")]
    [InlineData("co.uk")]
    [InlineData("foo.ck")]
    [InlineData("blogspot.com")]
    public void TheValidatorRefusesSharedSuffixes(string name)
    {
        var validator = new DomainNameValidator(List);

        Assert.Equal("DomainIsPublicSuffix", Assert.Throws<ServiceException>(() => validator.Normalize(name)).Code);
    }

    [Fact]
    public void ASingleLabelIsNotADomain_WhateverTheList() =>
        Assert.Equal("DomainInvalid", Assert.Throws<ServiceException>(() => new DomainNameValidator(List).Normalize("com")).Code);

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("MySite.GitHub.io", "mysite.github.io")]
    [InlineData("shop.co.uk.", "shop.co.uk")]
    [InlineData("www.ck", "www.ck")]
    public void TheValidatorAcceptsNamesUnderThem(string name, string expected) =>
        Assert.Equal(expected, new DomainNameValidator(List).Normalize(name));

    [Fact]
    public void TheValidatorHasNoDefaultList()
    {
        // There is no parameterless constructor: a placeholder list can never be used by accident.
        Assert.DoesNotContain(typeof(DomainNameValidator).GetConstructors(), c => c.GetParameters().Length == 0);
        Assert.Throws<ArgumentNullException>(() => new DomainNameValidator(null!));
    }
}

/// <summary>
/// The real list, bundled into the build. These fail until the data file is fetched once (see Data/README.md), which is
/// the point: the API refuses to start without it, and so must the tests. There are three, so a missing file is one
/// clear message and not a wall of red.
/// </summary>
public class BundledPublicSuffixListTests
{
    private static PublicSuffixList Bundled()
    {
        try
        {
            return PublicSuffixList.LoadEmbedded();
        }
        catch (InvalidOperationException ex)
        {
            Assert.Fail(ex.Message);
            throw;
        }
    }

    [Fact]
    public void TheListIsBundled_AndParsesCompletely() =>
        Assert.True(Bundled().RuleCount > 5000, "The bundled Public Suffix List looks truncated. Fetch it again: " + PublicSuffixList.FetchCommand);

    [Fact]
    public void TheListKnowsLongStandingSuffixes_AndNotOrdinaryNames()
    {
        var list = Bundled();
        var idn = new System.Globalization.IdnMapping();

        // ICANN section, private section, a wildcard rule (*.ck), a wildcard family (*.kobe.jp) and an internationalized rule.
        foreach (var suffix in new[] { "com", "org", "co.uk", "com.pk", "edu.pk", "github.io", "blogspot.com", "foo.ck", "c.kobe.jp", "k12.ak.us", idn.GetAscii("公司") + ".cn" })
            Assert.True(list.IsPublicSuffix(suffix), $"{suffix} should be a public suffix");
        // Exception rules (!www.ck, !city.kobe.jp) and ordinary names under a suffix.
        foreach (var ordinary in new[] { "example.com", "shop.co.uk", "mysite.github.io", "www.ck", "city.kobe.jp" })
            Assert.False(list.IsPublicSuffix(ordinary), $"{ordinary} should not be a public suffix");
        Assert.Equal("city.kobe.jp", list.GetRegistrableDomain("www.city.kobe.jp"));
        Assert.Equal("b.c.kobe.jp", list.GetRegistrableDomain("a.b.c.kobe.jp"));
    }

    [Fact]
    public void TheFileIsTheCompleteUnmodifiedList_WithItsLicenceHeader()
    {
        var assembly = typeof(PublicSuffixList).Assembly;
        using var stream = assembly.GetManifestResourceStream(PublicSuffixList.EmbeddedResourceName)
                           ?? throw new Xunit.Sdk.XunitException("The Public Suffix List is not bundled. Fetch it: " + PublicSuffixList.FetchCommand);
        var text = new StreamReader(stream).ReadToEnd();

        Assert.Contains("Mozilla Public", text);                    // the licence header is kept
        Assert.Contains("===BEGIN ICANN DOMAINS===", text);
        Assert.Contains("===END ICANN DOMAINS===", text);
        Assert.Contains("===BEGIN PRIVATE DOMAINS===", text);
        Assert.Contains("===END PRIVATE DOMAINS===", text);         // not truncated
        Assert.True(text.Length > 100_000, "The Public Suffix List looks truncated.");
    }

    [Fact]
    public void TheListTravelsInsideTheBuiltAssembly_NotAsALooseFile()
    {
        // An embedded resource is part of CipherSurface.Services.dll, so every build, test run, publish and container image
        // carries it. Nothing is read from the source tree or from a file next to the program.
        var assembly = typeof(PublicSuffixList).Assembly;
        var info = assembly.GetManifestResourceInfo(PublicSuffixList.EmbeddedResourceName);

        Assert.NotNull(info);
        Assert.True(info!.ResourceLocation.HasFlag(System.Reflection.ResourceLocation.Embedded));
        Assert.True(File.Exists(assembly.Location), "The assembly the list is read from is the one in the build output.");
        Assert.StartsWith(Path.GetFullPath(AppContext.BaseDirectory), Path.GetFullPath(assembly.Location), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheValidatorUsesIt()
    {
        var validator = new DomainNameValidator(Bundled());

        Assert.Equal("DomainIsPublicSuffix", Assert.Throws<ServiceException>(() => validator.Normalize("co.uk")).Code);
        Assert.Equal("example.org", validator.Normalize("example.org"));
    }
}
