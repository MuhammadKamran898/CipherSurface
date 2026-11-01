using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace CipherSurface.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "organizations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_organizations", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false),
                    user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    normalized_user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    normalized_email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    email_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                    password_hash = table.Column<string>(type: "text", nullable: true),
                    security_stamp = table.Column<string>(type: "text", nullable: true),
                    concurrency_stamp = table.Column<string>(type: "text", nullable: true),
                    phone_number = table.Column<string>(type: "text", nullable: true),
                    phone_number_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                    two_factor_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    lockout_end = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    lockout_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    access_failed_count = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_users", x => x.id);
                    table.CheckConstraint("ck_users_email_lower", "email = lower(email)");
                });

            migrationBuilder.CreateTable(
                name: "audit_logs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    sequence = table.Column<long>(type: "bigint", nullable: false),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    actor_type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    actor_id = table.Column<Guid>(type: "uuid", nullable: true),
                    action = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    entity_type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    entity_id = table.Column<Guid>(type: "uuid", nullable: true),
                    data = table.Column<string>(type: "jsonb", nullable: false),
                    ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    prev_hash = table.Column<byte[]>(type: "bytea", nullable: true),
                    hash = table.Column<byte[]>(type: "bytea", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_logs", x => x.id);
                    table.CheckConstraint("ck_audit_prev_hash_chain", "(sequence = 1) = (prev_hash IS NULL)");
                    table.CheckConstraint("ck_audit_sequence_positive", "sequence >= 1");
                    table.ForeignKey(
                        name: "fk_audit_logs_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "domains",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_domains", x => x.id);
                    table.CheckConstraint("ck_domains_name_lower", "name = lower(name)");
                    table.ForeignKey(
                        name: "fk_domains_asp_net_users_created_by_user_id",
                        column: x => x.created_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_domains_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "memberships",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_memberships", x => x.id);
                    table.ForeignKey(
                        name: "fk_memberships_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_memberships_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    family_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_reason = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    replaced_by_token_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_by_ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_refresh_tokens", x => x.id);
                    table.CheckConstraint("ck_refresh_tokens_expiry_after_creation", "expires_at > created_at");
                    table.CheckConstraint("ck_refresh_tokens_revoked_consistent", "(revoked_at IS NULL) = (revoked_reason IS NULL)");
                    table.ForeignKey(
                        name: "fk_refresh_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "user_claims",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    claim_type = table.Column<string>(type: "text", nullable: true),
                    claim_value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_user_claims_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_logins",
                columns: table => new
                {
                    login_provider = table.Column<string>(type: "text", nullable: false),
                    provider_key = table.Column<string>(type: "text", nullable: false),
                    provider_display_name = table.Column<string>(type: "text", nullable: true),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_logins", x => new { x.login_provider, x.provider_key });
                    table.ForeignKey(
                        name: "fk_user_logins_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_tokens",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    login_provider = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_tokens", x => new { x.user_id, x.login_provider, x.name });
                    table.ForeignKey(
                        name: "fk_user_tokens_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "authorization_grants",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    granted_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    grant_type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    attestation_text_version = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    attestation_hash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    accepted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_authorization_grants", x => x.id);
                    table.CheckConstraint("ck_grants_revoked_consistent", "(status = 'Revoked') = (revoked_at IS NOT NULL)");
                    table.ForeignKey(
                        name: "fk_authorization_grants_asp_net_users_granted_by_user_id",
                        column: x => x.granted_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_authorization_grants_asp_net_users_revoked_by_user_id",
                        column: x => x.revoked_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_authorization_grants_domains_domain_id",
                        column: x => x.domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_authorization_grants_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "domain_disputes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    incumbent_domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    claimant_domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    opened_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resolved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    resolved_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    note = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_domain_disputes", x => x.id);
                    table.CheckConstraint("ck_disputes_distinct_domains", "incumbent_domain_id <> claimant_domain_id");
                    table.CheckConstraint("ck_disputes_resolved_consistent", "(status = 'Open') = (resolved_at IS NULL)");
                    table.ForeignKey(
                        name: "fk_domain_disputes_asp_net_users_resolved_by_user_id",
                        column: x => x.resolved_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_domain_disputes_domains_claimant_domain_id",
                        column: x => x.claimant_domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_domain_disputes_domains_incumbent_domain_id",
                        column: x => x.incumbent_domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "policy_decisions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    trigger = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    failed_check_code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    effective_scope_snapshot = table.Column<string>(type: "jsonb", nullable: false),
                    evidence_ids = table.Column<Guid[]>(type: "uuid[]", nullable: false),
                    scope_rules_hash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    decided_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_policy_decisions", x => x.id);
                    table.CheckConstraint("ck_decisions_deny_has_code", "(outcome = 'Deny') = (failed_check_code IS NOT NULL)");
                    table.CheckConstraint("ck_decisions_expiry_after_decision", "expires_at > decided_at");
                    table.ForeignKey(
                        name: "fk_policy_decisions_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_policy_decisions_domains_domain_id",
                        column: x => x.domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_policy_decisions_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "scope_rules",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    rule_type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    pattern = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    removed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scope_rules", x => x.id);
                    table.CheckConstraint("ck_scope_rules_pattern_lower", "pattern = lower(pattern)");
                    table.ForeignKey(
                        name: "fk_scope_rules_asp_net_users_created_by_user_id",
                        column: x => x.created_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_scope_rules_domains_domain_id",
                        column: x => x.domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "verification_challenges",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    method = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    host = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    token = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    token_is_hashed = table.Column<bool>(type: "boolean", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    max_attempts = table.Column<int>(type: "integer", nullable: false),
                    issued_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_challenges", x => x.id);
                    table.CheckConstraint("ck_challenges_expiry_after_issue", "expires_at > issued_at");
                    table.CheckConstraint("ck_challenges_max_attempts", "max_attempts BETWEEN 1 AND 20");
                    table.ForeignKey(
                        name: "fk_verification_challenges_domains_domain_id",
                        column: x => x.domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "scan_runs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    policy_decision_id = table.Column<Guid>(type: "uuid", nullable: false),
                    schedule_id = table.Column<Guid>(type: "uuid", nullable: true),
                    scheduled_for = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    targets = table.Column<string[]>(type: "text[]", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    lease_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cancel_requested_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cancel_reason = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    finished_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_runs", x => x.id);
                    table.CheckConstraint("ck_scan_runs_cancel_pair", "(cancel_requested_at IS NULL) = (cancel_reason IS NULL)");
                    table.CheckConstraint("ck_scan_runs_cancel_status", "status NOT IN ('CancelRequested', 'Cancelled') OR cancel_requested_at IS NOT NULL");
                    table.CheckConstraint("ck_scan_runs_has_targets", "cardinality(targets) > 0");
                    table.CheckConstraint("ck_scan_runs_schedule_pair", "(schedule_id IS NULL) = (scheduled_for IS NULL)");
                    table.ForeignKey(
                        name: "fk_scan_runs_policy_decisions_policy_decision_id",
                        column: x => x.policy_decision_id,
                        principalTable: "policy_decisions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "verification_attempts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    challenge_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    result = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_attempts", x => x.id);
                    table.ForeignKey(
                        name: "fk_verification_attempts_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_verification_attempts_verification_challenges_challenge_id",
                        column: x => x.challenge_id,
                        principalTable: "verification_challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "verification_evidence",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain_id = table.Column<Guid>(type: "uuid", nullable: false),
                    challenge_id = table.Column<Guid>(type: "uuid", nullable: false),
                    method = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    assurance = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    scope_ceiling_type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    host = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    established_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_checked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_valid_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failing_since = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_evidence", x => x.id);
                    table.CheckConstraint("ck_evidence_email_expires", "method <> 'AdminEmail' OR expires_at IS NOT NULL");
                    table.CheckConstraint("ck_evidence_email_root_only", "method <> 'AdminEmail' OR scope_ceiling_type = 'RootOnly'");
                    table.CheckConstraint("ck_evidence_failing_since_active", "status <> 'Active' OR failing_since IS NULL");
                    table.CheckConstraint("ck_evidence_failing_since_atrisk", "status <> 'AtRisk' OR failing_since IS NOT NULL");
                    table.CheckConstraint("ck_evidence_wildcard_dns_only", "scope_ceiling_type <> 'DomainAndSubdomains' OR method = 'DnsTxt'");
                    table.ForeignKey(
                        name: "fk_verification_evidence_domains_domain_id",
                        column: x => x.domain_id,
                        principalTable: "domains",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_verification_evidence_verification_challenges_challenge_id",
                        column: x => x.challenge_id,
                        principalTable: "verification_challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "scan_run_authorization_checks",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    scan_run_id = table.Column<Guid>(type: "uuid", nullable: false),
                    sequence = table.Column<int>(type: "integer", nullable: false),
                    checked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    reason_code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    scope_hash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    targets_remaining = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_run_authorization_checks", x => x.id);
                    table.CheckConstraint("ck_scan_checks_sequence_positive", "sequence >= 1");
                    table.ForeignKey(
                        name: "fk_scan_run_authorization_checks_scan_runs_scan_run_id",
                        column: x => x.scan_run_id,
                        principalTable: "scan_runs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "verification_checks",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    attempt_id = table.Column<Guid>(type: "uuid", nullable: true),
                    evidence_id = table.Column<Guid>(type: "uuid", nullable: true),
                    check_run_id = table.Column<Guid>(type: "uuid", nullable: true),
                    retry_number = table.Column<int>(type: "integer", nullable: false),
                    checked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    triggered_by = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    detail = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_checks", x => x.id);
                    table.CheckConstraint("ck_checks_exactly_one_parent", "(attempt_id IS NOT NULL) <> (evidence_id IS NOT NULL)");
                    table.CheckConstraint("ck_checks_retry_nonneg", "retry_number >= 0");
                    table.CheckConstraint("ck_checks_system_has_run_id", "evidence_id IS NULL OR check_run_id IS NOT NULL");
                    table.ForeignKey(
                        name: "fk_verification_checks_verification_attempts_attempt_id",
                        column: x => x.attempt_id,
                        principalTable: "verification_attempts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_verification_checks_verification_evidence_evidence_id",
                        column: x => x.evidence_id,
                        principalTable: "verification_evidence",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_logs_entity_type_entity_id",
                table: "audit_logs",
                columns: new[] { "entity_type", "entity_id" });

            migrationBuilder.CreateIndex(
                name: "ix_audit_logs_organization_id_occurred_at",
                table: "audit_logs",
                columns: new[] { "organization_id", "occurred_at" });

            migrationBuilder.CreateIndex(
                name: "ix_audit_logs_organization_id_sequence",
                table: "audit_logs",
                columns: new[] { "organization_id", "sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_authorization_grants_granted_by_user_id",
                table: "authorization_grants",
                column: "granted_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_grants_organization_id",
                table: "authorization_grants",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_grants_revoked_by_user_id",
                table: "authorization_grants",
                column: "revoked_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ux_grants_one_active_per_domain",
                table: "authorization_grants",
                column: "domain_id",
                unique: true,
                filter: "status = 'Active'");

            migrationBuilder.CreateIndex(
                name: "ix_domain_disputes_incumbent_domain_id",
                table: "domain_disputes",
                column: "incumbent_domain_id");

            migrationBuilder.CreateIndex(
                name: "ix_domain_disputes_resolved_by_user_id",
                table: "domain_disputes",
                column: "resolved_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ux_disputes_one_open_per_claimant",
                table: "domain_disputes",
                column: "claimant_domain_id",
                unique: true,
                filter: "status = 'Open'");

            migrationBuilder.CreateIndex(
                name: "ix_domains_created_by_user_id",
                table: "domains",
                column: "created_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ix_domains_organization_id_name",
                table: "domains",
                columns: new[] { "organization_id", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_domains_active_holder",
                table: "domains",
                column: "name",
                unique: true,
                filter: "status IN ('Verified', 'AtRisk')");

            migrationBuilder.CreateIndex(
                name: "ix_memberships_organization_id_user_id",
                table: "memberships",
                columns: new[] { "organization_id", "user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_memberships_user_id",
                table: "memberships",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_policy_decisions_domain_id_decided_at",
                table: "policy_decisions",
                columns: new[] { "domain_id", "decided_at" });

            migrationBuilder.CreateIndex(
                name: "ix_policy_decisions_organization_id",
                table: "policy_decisions",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "ix_policy_decisions_user_id",
                table: "policy_decisions",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_token_hash",
                table: "refresh_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_user_id",
                table: "refresh_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_scan_run_authorization_checks_scan_run_id_sequence",
                table: "scan_run_authorization_checks",
                columns: new[] { "scan_run_id", "sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_policy_decision_id",
                table: "scan_runs",
                column: "policy_decision_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_status",
                table: "scan_runs",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "ux_scan_runs_schedule_occurrence",
                table: "scan_runs",
                columns: new[] { "schedule_id", "scheduled_for" },
                unique: true,
                filter: "schedule_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_scope_rules_created_by_user_id",
                table: "scope_rules",
                column: "created_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ix_scope_rules_live",
                table: "scope_rules",
                column: "domain_id",
                filter: "removed_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_user_claims_user_id",
                table: "user_claims",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_logins_user_id",
                table: "user_logins",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "users",
                column: "normalized_email");

            migrationBuilder.CreateIndex(
                name: "ix_users_email",
                table: "users",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "users",
                column: "normalized_user_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_verification_attempts_challenge_id",
                table: "verification_attempts",
                column: "challenge_id");

            migrationBuilder.CreateIndex(
                name: "ix_verification_attempts_ip_started_at",
                table: "verification_attempts",
                columns: new[] { "ip", "started_at" });

            migrationBuilder.CreateIndex(
                name: "ix_verification_attempts_user_id_started_at",
                table: "verification_attempts",
                columns: new[] { "user_id", "started_at" });

            migrationBuilder.CreateIndex(
                name: "ix_verification_challenges_status_expires_at",
                table: "verification_challenges",
                columns: new[] { "status", "expires_at" });

            migrationBuilder.CreateIndex(
                name: "ux_challenges_one_active_per_method",
                table: "verification_challenges",
                columns: new[] { "domain_id", "method" },
                unique: true,
                filter: "status IN ('Issued', 'Checking')");

            migrationBuilder.CreateIndex(
                name: "ix_verification_checks_evidence_id_checked_at",
                table: "verification_checks",
                columns: new[] { "evidence_id", "checked_at" });

            migrationBuilder.CreateIndex(
                name: "ux_checks_attempt_retry",
                table: "verification_checks",
                columns: new[] { "attempt_id", "retry_number" },
                unique: true,
                filter: "attempt_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_checks_run_retry",
                table: "verification_checks",
                columns: new[] { "check_run_id", "retry_number" },
                unique: true,
                filter: "check_run_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_verification_evidence_challenge_id",
                table: "verification_evidence",
                column: "challenge_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_verification_evidence_domain_id_status",
                table: "verification_evidence",
                columns: new[] { "domain_id", "status" });

            migrationBuilder.CreateIndex(
                name: "ix_verification_evidence_status_failing_since",
                table: "verification_evidence",
                columns: new[] { "status", "failing_since" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_logs");

            migrationBuilder.DropTable(
                name: "authorization_grants");

            migrationBuilder.DropTable(
                name: "domain_disputes");

            migrationBuilder.DropTable(
                name: "memberships");

            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropTable(
                name: "scan_run_authorization_checks");

            migrationBuilder.DropTable(
                name: "scope_rules");

            migrationBuilder.DropTable(
                name: "user_claims");

            migrationBuilder.DropTable(
                name: "user_logins");

            migrationBuilder.DropTable(
                name: "user_tokens");

            migrationBuilder.DropTable(
                name: "verification_checks");

            migrationBuilder.DropTable(
                name: "scan_runs");

            migrationBuilder.DropTable(
                name: "verification_attempts");

            migrationBuilder.DropTable(
                name: "verification_evidence");

            migrationBuilder.DropTable(
                name: "policy_decisions");

            migrationBuilder.DropTable(
                name: "verification_challenges");

            migrationBuilder.DropTable(
                name: "domains");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "organizations");
        }
    }
}
