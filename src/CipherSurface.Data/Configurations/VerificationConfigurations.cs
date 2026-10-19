using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CipherSurface.Data.Configurations;

public class VerificationChallengeConfiguration : IEntityTypeConfiguration<VerificationChallenge>
{
    public void Configure(EntityTypeBuilder<VerificationChallenge> b)
    {
        b.ToTable("verification_challenges", t =>
        {
            t.HasCheckConstraint("ck_challenges_expiry_after_issue", "expires_at > issued_at");
            t.HasCheckConstraint("ck_challenges_max_attempts", "max_attempts BETWEEN 1 AND 20");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Host).HasMaxLength(253).IsRequired();
        b.Property(x => x.Token).HasMaxLength(128).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.Domain).WithMany(d => d.Challenges)
            .HasForeignKey(x => x.DomainId).OnDelete(DeleteBehavior.Restrict);

        // One active challenge per domain and method. Regenerating supersedes the old one
        // in the same transaction.
        b.HasIndex(x => new { x.DomainId, x.Method })
            .IsUnique()
            .HasFilter("status IN ('Issued', 'Checking')")
            .HasDatabaseName("ux_challenges_one_active_per_method");

        // Used by the ExpireChallenges job.
        b.HasIndex(x => new { x.Status, x.ExpiresAt });
    }
}

public class VerificationAttemptConfiguration : IEntityTypeConfiguration<VerificationAttempt>
{
    public void Configure(EntityTypeBuilder<VerificationAttempt> b)
    {
        b.ToTable("verification_attempts");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Ip).HasMaxLength(45).IsRequired();

        b.HasOne(x => x.Challenge).WithMany(c => c.Attempts)
            .HasForeignKey(x => x.ChallengeId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);

        // Rate-limit queries: attempts per user / per IP over a time window.
        b.HasIndex(x => new { x.UserId, x.StartedAt });
        b.HasIndex(x => new { x.Ip, x.StartedAt });
    }
}

public class VerificationEvidenceConfiguration : IEntityTypeConfiguration<VerificationEvidence>
{
    public void Configure(EntityTypeBuilder<VerificationEvidence> b)
    {
        b.ToTable("verification_evidence", t =>
        {
            // Wildcard scope can only ever come from DNS evidence.
            t.HasCheckConstraint("ck_evidence_wildcard_dns_only",
                "scope_ceiling_type <> 'DomainAndSubdomains' OR method = 'DnsTxt'");
            // Email evidence is root-domain only and always expires.
            t.HasCheckConstraint("ck_evidence_email_root_only",
                "method <> 'AdminEmail' OR scope_ceiling_type = 'RootOnly'");
            t.HasCheckConstraint("ck_evidence_email_expires",
                "method <> 'AdminEmail' OR expires_at IS NOT NULL");
            // failing_since is set exactly while the evidence is not healthy.
            t.HasCheckConstraint("ck_evidence_failing_since_atrisk",
                "status <> 'AtRisk' OR failing_since IS NOT NULL");
            t.HasCheckConstraint("ck_evidence_failing_since_active",
                "status <> 'Active' OR failing_since IS NULL");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Host).HasMaxLength(253).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.Domain).WithMany(d => d.Evidence)
            .HasForeignKey(x => x.DomainId).OnDelete(DeleteBehavior.Restrict);

        // One evidence row per challenge: a retried job cannot create a duplicate.
        b.HasOne(x => x.Challenge).WithOne(c => c.Evidence)
            .HasForeignKey<VerificationEvidence>(x => x.ChallengeId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => new { x.DomainId, x.Status });
        b.HasIndex(x => new { x.Status, x.FailingSince });   // EvidenceLifecycle job
    }
}

public class VerificationCheckConfiguration : IEntityTypeConfiguration<VerificationCheck>
{
    public void Configure(EntityTypeBuilder<VerificationCheck> b)
    {
        b.ToTable("verification_checks", t =>
        {
            t.HasCheckConstraint("ck_checks_exactly_one_parent",
                "(attempt_id IS NOT NULL) <> (evidence_id IS NOT NULL)");
            t.HasCheckConstraint("ck_checks_system_has_run_id",
                "evidence_id IS NULL OR check_run_id IS NOT NULL");
            t.HasCheckConstraint("ck_checks_retry_nonneg", "retry_number >= 0");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Detail).HasColumnType("jsonb").IsRequired();

        b.HasOne(x => x.Attempt).WithMany(a => a.Checks)
            .HasForeignKey(x => x.AttemptId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne(x => x.Evidence).WithMany(e => e.Checks)
            .HasForeignKey(x => x.EvidenceId).OnDelete(DeleteBehavior.Restrict);

        // Idempotency: a retried job reuses its key and hits these constraints harmlessly,
        // while a genuinely new daily or pre-scan check gets a new check_run_id.
        b.HasIndex(x => new { x.AttemptId, x.RetryNumber })
            .IsUnique()
            .HasFilter("attempt_id IS NOT NULL")
            .HasDatabaseName("ux_checks_attempt_retry");
        b.HasIndex(x => new { x.CheckRunId, x.RetryNumber })
            .IsUnique()
            .HasFilter("check_run_id IS NOT NULL")
            .HasDatabaseName("ux_checks_run_retry");

        b.HasIndex(x => new { x.EvidenceId, x.CheckedAt });
    }
}
