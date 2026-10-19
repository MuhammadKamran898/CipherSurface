# CipherSurface

**Domain verification and scan authorization foundation** for the CipherSurface Final Year Project.

This repository contains the EF Core data model, the database-free policy logic, and automated tests for the ownership-verification and scan-authorization foundation. Project names describe their responsibilities; the repository does not use temporary step numbers in folder or solution names.

## Repository structure

```text
CipherSurface/
├── CipherSurface.sln
├── global.json
├── README.md
├── .gitignore
├── src/
│   ├── CipherSurface.Data/
│   │   ├── Configurations/
│   │   ├── Entities/
│   │   ├── Enums/
│   │   ├── Sql/
│   │   └── CipherSurface.Data.csproj
│   └── CipherSurface.Policy/
│       ├── EvidenceUsabilityEvaluator.cs
│       ├── ScanContinuationGate.cs
│       ├── ScanPolicyGate.cs
│       ├── ScopeCalculator.cs
│       └── CipherSurface.Policy.csproj
└── tests/
    └── CipherSurface.Policy.Tests/
        └── CipherSurface.Policy.Tests.csproj
```

### Projects

- **`CipherSurface.Data`** — EF Core entities and configurations, `DbContext`, PostgreSQL integrity SQL, and design-time configuration.
- **`CipherSurface.Policy`** — deterministic scope calculation, evidence usability evaluation, scan-start authorization, and execution-time continuation policy. It does not make network calls or persist database changes.
- **`CipherSurface.Policy.Tests`** — xUnit tests for policy logic and scope behavior.

The API/service orchestration, ownership-verifier network implementations, Hangfire job handlers, transactional persistence, audit-hash computation, worker HMAC validation, and worker lease endpoints are not included in these projects yet; they belong in the corresponding application/infrastructure projects as implementation continues.

## Prerequisites

- .NET SDK 10. The development setup for this project uses SDK `10.0.401`.
- NuGet package-source access for the first restore.
- PostgreSQL 16 for database setup and SQL integrity tests. PostgreSQL is not required to run the pure policy unit tests.

The root `global.json` selects Microsoft Testing Platform for `dotnet test`. Keep it next to `CipherSurface.sln`.

## Build and test (PowerShell)

Run these commands from the directory containing `CipherSurface.sln`:

```powershell
dotnet --version
dotnet restore .\CipherSurface.sln
dotnet build .\CipherSurface.sln --no-restore
dotnet test --project .\tests\CipherSurface.Policy.Tests\CipherSurface.Policy.Tests.csproj
```

For subsequent test runs after a successful build:

```powershell
dotnet test --project .\tests\CipherSurface.Policy.Tests\CipherSurface.Policy.Tests.csproj --no-build
```

If restore fails, resolve the reported NuGet source/network issue before using `--no-restore`. If the test command reports that the MTP runner is not enabled, confirm that PowerShell is running from this repository root and that `global.json` is beside the solution.

## Database setup

Read [`src/CipherSurface.Data/README.md`](src/CipherSurface.Data/README.md) for the data-layer setup and SQL script order. Run migrations with the database-owner role, then apply the application-role grants using the restricted application role design described there. Do not run owner credentials in the application process.

## Implementation boundaries

The policy library returns decisions and proposed state changes. The API/service layer must load a fresh state snapshot, run live verification before evaluating the final gate, and persist verification checks, evidence updates, status recalculation, the policy decision, and audit records transactionally. A worker must never receive a scan request without persisted authorization and a valid signed, unexpired, scope-bounded payload.

## Validation status

The `CipherSurface.Data` project was reported to build without warnings on .NET SDK `10.0.401` in the developer's environment. The policy project and unit tests must also be built and run in that environment before treating the complete solution as verified. This archive has been reorganized and project paths adjusted, but compilation/test execution was not available in the packaging environment.
