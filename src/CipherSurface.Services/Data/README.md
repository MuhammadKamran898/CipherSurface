# Public Suffix List

`PublicSuffixList` decides which names are shared suffixes (`com`, `co.uk`, `github.io`) that nobody owns, so a domain
onboarding request for one is refused. It reads the official list from `public_suffix_list.dat` in this folder.

## How it reaches the running application

The file is an **embedded resource**: the build compiles it into `CipherSurface.Services.dll`. That is deliberate, not a
copy-to-output setting. Every build, test run, `dotnet publish` and container image carries it automatically, nothing is
read from the source tree or from a file next to the program, and nothing is downloaded when the application starts or
when a domain is validated.

The file is a **required build asset**: if it is missing, the build of `CipherSurface.Services` fails with error `CSPSL001`
and the command to fetch it, instead of producing an assembly without it. As a second line of defence an assembly built any
other way refuses to start without it (there is no fallback list), and the start-up log says which list was loaded.

## What is committed

| | |
|---|---|
| File | `src/CipherSurface.Services/Data/public_suffix_list.dat`, unmodified (licence header and both sections intact) |
| Retrieved | 2026-11-07 from `https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat`, the project repository the website publishes from |
| SHA-256 | `762b6cbdd2dacc597b398fcd7860e2184b684125a58aa177dbdf54916a1f3430` |
| Size | 338,457 bytes, 16,581 lines, 10,406 rules (314 wildcard, 8 exception, 459 internationalized) |
| Git | `.gitattributes` marks it `-text`, so no platform converts its line endings and the bytes stay identical after a clone |

The list's own header asks to be pulled from `publicsuffix.org`. To check the committed copy against that source, or to refresh it:

```powershell
# from the repository root
Invoke-WebRequest https://publicsuffix.org/list/public_suffix_list.dat -OutFile src/CipherSurface.Services/Data/public_suffix_list.dat
Get-FileHash src/CipherSurface.Services/Data/public_suffix_list.dat -Algorithm SHA256
```

If the hash differs from the one above the list has simply been updated since. Keep the new file, run the tests, update the
hash and date in this table, and commit. The tests do not depend on a particular version.

## Behaviour

- Both sections are used: the ICANN section and the private section (shared hosts such as `github.io`).
- The parser follows the format specification: an exception rule prevails, otherwise the rule with the most labels,
  otherwise the implicit `*`. Wildcard (`*.ck`), exception (`!www.ck`) and internationalized rules are all supported.
- A rule that cannot be read stops the load with its line number. A rule silently skipped would make a public suffix look
  registrable.
- To try another copy without rebuilding, set `CipherSurface:Verification:PublicSuffixListFile`.
- **Licence:** the list is published under the Mozilla Public License 2.0 (https://publicsuffix.org/). Keep it as a
  separate, unmodified data file.

## Verifying a deployment

After publishing, check two things: the list is inside the published assembly, and the published application loads it
when it starts. In PowerShell 7, from the repository root:

```powershell
# 1. Publish the way a deployment does (the folder is git-ignored).
dotnet publish src/CipherSurface.Api -c Release -o .artifacts/2b0-publish

# 2. The list must be inside the published assembly.
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path ".artifacts/2b0-publish/CipherSurface.Services.dll").Path)
$stream = $assembly.GetManifestResourceStream("CipherSurface.Services.public_suffix_list.dat")
if ($null -eq $stream -or $stream.Length -eq 0) { throw "The Public Suffix List is missing from the published Services assembly." }
"Embedded Public Suffix List: $($stream.Length) bytes"
$stream.Dispose()

# 3. The published application must load it at start-up. A throwaway key and an unused connection string are enough:
#    nothing connects to a database until a request needs one.
$key = Join-Path $env:TEMP "psl-check-key.pem"
[System.Security.Cryptography.RSA]::Create(2048).ExportPkcs8PrivateKeyPem() | Set-Content $key
$env:CipherSurface__Jwt__PrivateKeyFile = $key
$env:CipherSurface__Jwt__KeyId = "check"
$env:ConnectionStrings__CipherSurface = "Host=localhost;Database=unused"
$env:ASPNETCORE_URLS = "http://127.0.0.1:5088"
dotnet .artifacts/2b0-publish/CipherSurface.Api.dll
# Expect "Public Suffix List loaded: <n> rules from the embedded resource", then "Now listening on: http://127.0.0.1:5088".
# Press Ctrl+C to stop. Remove the key afterwards: Remove-Item $key
```
