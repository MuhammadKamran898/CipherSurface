using CipherSurface.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Data;

/// <summary>Identity user tables without Identity roles: roles are per organization and live in Membership.</summary>
public class CipherSurfaceDbContext : IdentityUserContext<User, Guid>
{
    public CipherSurfaceDbContext(DbContextOptions<CipherSurfaceDbContext> options) : base(options) { }

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<Membership> Memberships => Set<Membership>();
    public DbSet<AuthorizationGrant> AuthorizationGrants => Set<AuthorizationGrant>();

    public DbSet<Domain> Domains => Set<Domain>();
    public DbSet<DomainDispute> DomainDisputes => Set<DomainDispute>();
    public DbSet<VerificationChallenge> VerificationChallenges => Set<VerificationChallenge>();
    public DbSet<VerificationAttempt> VerificationAttempts => Set<VerificationAttempt>();
    public DbSet<VerificationEvidence> VerificationEvidence => Set<VerificationEvidence>();
    public DbSet<VerificationCheck> VerificationChecks => Set<VerificationCheck>();

    public DbSet<ScopeRule> ScopeRules => Set<ScopeRule>();
    public DbSet<PolicyDecision> PolicyDecisions => Set<PolicyDecision>();
    public DbSet<ScanRun> ScanRuns => Set<ScanRun>();
    public DbSet<ScanRunAuthorizationCheck> ScanRunAuthorizationChecks => Set<ScanRunAuthorizationCheck>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);   // Identity's user, claim, login and token tables

        modelBuilder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
        modelBuilder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
        modelBuilder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");

        modelBuilder.ApplyConfigurationsFromAssembly(typeof(CipherSurfaceDbContext).Assembly);

        // Store every enum as a string. Partial-index filters and check constraints in the
        // configurations compare against these string values.
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                var clrType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
                if (clrType.IsEnum)
                {
                    property.SetProviderClrType(typeof(string));
                    property.SetMaxLength(32);
                }
            }
        }
    }
}
