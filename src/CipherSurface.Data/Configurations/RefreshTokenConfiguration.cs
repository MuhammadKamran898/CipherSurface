using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CipherSurface.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> b)
    {
        b.ToTable("refresh_tokens", t =>
        {
            t.HasCheckConstraint("ck_refresh_tokens_expiry_after_creation", "expires_at > created_at");
            t.HasCheckConstraint("ck_refresh_tokens_revoked_consistent", "(revoked_at IS NULL) = (revoked_reason IS NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).ValueGeneratedNever();
        b.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
        b.Property(x => x.RevokedReason).HasMaxLength(40);
        b.Property(x => x.CreatedByIp).HasMaxLength(45).IsRequired();
        b.Property(x => x.Version).IsRowVersion();

        b.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(x => x.TokenHash).IsUnique();
        b.HasIndex(x => x.FamilyId);
        b.HasIndex(x => x.UserId);
    }
}
