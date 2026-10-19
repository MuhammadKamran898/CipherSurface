using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CipherSurface.Data.Configurations;

public class DomainConfiguration : IEntityTypeConfiguration<Domain>
{
    public void Configure(EntityTypeBuilder<Domain> b)
    {
        b.ToTable("domains", t => t.HasCheckConstraint("ck_domains_name_lower", "name = lower(name)"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Name).HasMaxLength(253).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.Organization).WithMany(o => o.Domains)
            .HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.CreatedByUserId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => new { x.OrganizationId, x.Name }).IsUnique();

        // Invariant: only ONE organization may hold a domain name in Verified or AtRisk.
        // This index is the final arbiter of competing claims (spec section 8).
        b.HasIndex(x => x.Name)
            .IsUnique()
            .HasFilter("status IN ('Verified', 'AtRisk')")
            .HasDatabaseName("ux_domains_active_holder");
    }
}

public class AuthorizationGrantConfiguration : IEntityTypeConfiguration<AuthorizationGrant>
{
    public void Configure(EntityTypeBuilder<AuthorizationGrant> b)
    {
        b.ToTable("authorization_grants", t =>
            t.HasCheckConstraint("ck_grants_revoked_consistent",
                "(status = 'Revoked') = (revoked_at IS NOT NULL)"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.AttestationTextVersion).HasMaxLength(50).IsRequired();
        b.Property(x => x.AttestationHash).HasMaxLength(128).IsRequired();
        b.Property(x => x.Ip).HasMaxLength(45).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.Domain).WithMany(d => d.Grants)
            .HasForeignKey(x => x.DomainId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<Organization>().WithMany()
            .HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.GrantedByUserId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.RevokedByUserId).OnDelete(DeleteBehavior.Restrict);

        // One active grant per domain.
        b.HasIndex(x => x.DomainId)
            .IsUnique()
            .HasFilter("status = 'Active'")
            .HasDatabaseName("ux_grants_one_active_per_domain");
    }
}

public class DomainDisputeConfiguration : IEntityTypeConfiguration<DomainDispute>
{
    public void Configure(EntityTypeBuilder<DomainDispute> b)
    {
        b.ToTable("domain_disputes", t =>
        {
            t.HasCheckConstraint("ck_disputes_distinct_domains", "incumbent_domain_id <> claimant_domain_id");
            t.HasCheckConstraint("ck_disputes_resolved_consistent", "(status = 'Open') = (resolved_at IS NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Note).HasMaxLength(2000);
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.IncumbentDomain).WithMany()
            .HasForeignKey(x => x.IncumbentDomainId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne(x => x.ClaimantDomain).WithMany()
            .HasForeignKey(x => x.ClaimantDomainId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.ResolvedByUserId).OnDelete(DeleteBehavior.Restrict);

        // A claimant record can have only one open dispute.
        b.HasIndex(x => x.ClaimantDomainId)
            .IsUnique()
            .HasFilter("status = 'Open'")
            .HasDatabaseName("ux_disputes_one_open_per_claimant");
    }
}
