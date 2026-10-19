using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CipherSurface.Data.Configurations;

public class ScopeRuleConfiguration : IEntityTypeConfiguration<ScopeRule>
{
    public void Configure(EntityTypeBuilder<ScopeRule> b)
    {
        // "Pattern must fall under the domain" needs the domain's name, so it is enforced
        // by a trigger in Sql/001_integrity.sql, not by a check constraint.
        b.ToTable("scope_rules", t => t.HasCheckConstraint("ck_scope_rules_pattern_lower", "pattern = lower(pattern)"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Pattern).HasMaxLength(255).IsRequired();

        b.HasOne(x => x.Domain).WithMany(d => d.ScopeRules)
            .HasForeignKey(x => x.DomainId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.CreatedByUserId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => x.DomainId).HasFilter("removed_at IS NULL").HasDatabaseName("ix_scope_rules_live");
    }
}

public class PolicyDecisionConfiguration : IEntityTypeConfiguration<PolicyDecision>
{
    public void Configure(EntityTypeBuilder<PolicyDecision> b)
    {
        b.ToTable("policy_decisions", t =>
        {
            t.HasCheckConstraint("ck_decisions_deny_has_code",
                "(outcome = 'Deny') = (failed_check_code IS NOT NULL)");
            t.HasCheckConstraint("ck_decisions_expiry_after_decision", "expires_at > decided_at");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.FailedCheckCode).HasMaxLength(64);
        b.Property(x => x.EffectiveScopeSnapshot).HasColumnType("jsonb").IsRequired();
        b.Property(x => x.EvidenceIds).HasColumnType("uuid[]");
        b.Property(x => x.ScopeRulesHash).HasMaxLength(128).IsRequired();

        b.HasOne<Organization>().WithMany()
            .HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<Domain>().WithMany()
            .HasForeignKey(x => x.DomainId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => new { x.DomainId, x.DecidedAt });
    }
}

public class ScanRunConfiguration : IEntityTypeConfiguration<ScanRun>
{
    public void Configure(EntityTypeBuilder<ScanRun> b)
    {
        b.ToTable("scan_runs", t =>
        {
            t.HasCheckConstraint("ck_scan_runs_cancel_pair",
                "(cancel_requested_at IS NULL) = (cancel_reason IS NULL)");
            t.HasCheckConstraint("ck_scan_runs_cancel_status",
                "status NOT IN ('CancelRequested', 'Cancelled') OR cancel_requested_at IS NOT NULL");
            t.HasCheckConstraint("ck_scan_runs_schedule_pair",
                "(schedule_id IS NULL) = (scheduled_for IS NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.CancelReason).HasMaxLength(200);
        b.Property(x => x.Version).IsRowVersion();

        // NOT NULL + unique: a scan cannot exist without an Allow decision, and one
        // decision authorizes exactly one scan. (Outcome = Allow is checked by the
        // service layer and by the trigger in Sql/001_integrity.sql.)
        b.HasOne(x => x.PolicyDecision).WithOne(d => d.ScanRun)
            .HasForeignKey<ScanRun>(x => x.PolicyDecisionId)
            .IsRequired()
            .OnDelete(DeleteBehavior.Restrict);

        // One scan per schedule occurrence.
        b.HasIndex(x => new { x.ScheduleId, x.ScheduledFor })
            .IsUnique()
            .HasFilter("schedule_id IS NOT NULL")
            .HasDatabaseName("ux_scan_runs_schedule_occurrence");

        b.HasIndex(x => x.Status);
    }
}

public class ScanRunAuthorizationCheckConfiguration : IEntityTypeConfiguration<ScanRunAuthorizationCheck>
{
    public void Configure(EntityTypeBuilder<ScanRunAuthorizationCheck> b)
    {
        b.ToTable("scan_run_authorization_checks", t =>
            t.HasCheckConstraint("ck_scan_checks_sequence_positive", "sequence >= 1"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.ReasonCode).HasMaxLength(64);
        b.Property(x => x.ScopeHash).HasMaxLength(128).IsRequired();

        b.HasOne(x => x.ScanRun).WithMany(s => s.AuthorizationChecks)
            .HasForeignKey(x => x.ScanRunId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => new { x.ScanRunId, x.Sequence }).IsUnique();
    }
}

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> b)
    {
        b.ToTable("audit_logs", t =>
        {
            t.HasCheckConstraint("ck_audit_sequence_positive", "sequence >= 1");
            t.HasCheckConstraint("ck_audit_prev_hash_chain", "(sequence = 1) = (prev_hash IS NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.ActorType).HasMaxLength(32).IsRequired();
        b.Property(x => x.Action).HasMaxLength(100).IsRequired();
        b.Property(x => x.EntityType).HasMaxLength(64).IsRequired();
        b.Property(x => x.Data).HasColumnType("jsonb").IsRequired();
        b.Property(x => x.Ip).HasMaxLength(45);
        b.Property(x => x.PrevHash).HasColumnType("bytea");
        b.Property(x => x.Hash).HasColumnType("bytea").IsRequired();

        b.HasOne<Organization>().WithMany()
            .HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);

        // One chain per organization: sequence numbers are unique and gap-detectable.
        b.HasIndex(x => new { x.OrganizationId, x.Sequence }).IsUnique();
        b.HasIndex(x => new { x.OrganizationId, x.OccurredAt });
        b.HasIndex(x => new { x.EntityType, x.EntityId });
    }
}
