using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CipherSurface.Data.Configurations;

public class InvitationConfiguration : IEntityTypeConfiguration<Invitation>
{
    public void Configure(EntityTypeBuilder<Invitation> b)
    {
        b.ToTable("invitations", t =>
        {
            t.HasCheckConstraint("ck_invitations_email_lower", "email = lower(email)");
            // An allow-list, not "anything but Owner": EF reads role text case-insensitively, so a stored 'owner' would
            // be read back as Owner and an unknown value would make the row unreadable. The invitable roles are exactly these.
            t.HasCheckConstraint("ck_invitations_role_invitable", "role IN ('Admin', 'Analyst', 'Viewer')");
            // Exactly what OpaqueTokens.Hash produces: SHA-256 as 64 lower-case hex characters (lookups compare the string exactly).
            t.HasCheckConstraint("ck_invitations_token_hash_hex", "token_hash ~ '^[0-9a-f]{64}$'");
            t.HasCheckConstraint("ck_invitations_expiry_after_creation", "expires_at > created_at");
            t.HasCheckConstraint("ck_invitations_resolved_consistent",
                "(status = 'Pending') = (resolved_at IS NULL) AND (resolved_at IS NULL) = (resolved_by_user_id IS NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.Email).HasMaxLength(320).IsRequired();
        b.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.Organization).WithMany()
            .HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.CreatedByUserId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany()
            .HasForeignKey(x => x.ResolvedByUserId).OnDelete(DeleteBehavior.Restrict);

        // Looked up by the hash of the token someone presents. Unique, so two invitations can never share a token.
        b.HasIndex(x => x.TokenHash).IsUnique().HasDatabaseName("ux_invitations_token_hash");

        // One pending invitation per organization and email. Issuing again must supersede the old one first.
        b.HasIndex(x => new { x.OrganizationId, x.Email })
            .IsUnique()
            .HasFilter("status = 'Pending'")
            .HasDatabaseName("ux_invitations_one_pending");

        b.HasIndex(x => new { x.OrganizationId, x.CreatedAt }).HasDatabaseName("ix_invitations_organization");
    }
}
