using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CipherSurface.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddInvitations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "invitations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resolved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    resolved_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_invitations", x => x.id);
                    table.CheckConstraint("ck_invitations_email_lower", "email = lower(email)");
                    table.CheckConstraint("ck_invitations_expiry_after_creation", "expires_at > created_at");
                    table.CheckConstraint("ck_invitations_resolved_consistent", "(status = 'Pending') = (resolved_at IS NULL) AND (resolved_at IS NULL) = (resolved_by_user_id IS NULL)");
                    table.CheckConstraint("ck_invitations_role_invitable", "role IN ('Admin', 'Analyst', 'Viewer')");
                    table.CheckConstraint("ck_invitations_token_hash_hex", "token_hash ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "fk_invitations_asp_net_users_created_by_user_id",
                        column: x => x.created_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_invitations_asp_net_users_resolved_by_user_id",
                        column: x => x.resolved_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_invitations_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_invitations_created_by_user_id",
                table: "invitations",
                column: "created_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ix_invitations_organization",
                table: "invitations",
                columns: new[] { "organization_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "ix_invitations_resolved_by_user_id",
                table: "invitations",
                column: "resolved_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ux_invitations_one_pending",
                table: "invitations",
                columns: new[] { "organization_id", "email" },
                unique: true,
                filter: "status = 'Pending'");

            migrationBuilder.CreateIndex(
                name: "ux_invitations_token_hash",
                table: "invitations",
                column: "token_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "invitations");
        }
    }
}
