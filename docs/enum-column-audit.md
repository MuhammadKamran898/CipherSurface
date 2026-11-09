# Enum-backed column audit

**Status: documentation only.** Nothing here has been changed. The sweep that adds the constraints is planned after
Batch 2b, together with the `memberships.role` constraint.

Every enum in the model is stored as text (`HasMaxLength(32)`). Measured on the EF model at commit `86c3c7d`
(23 columns in 15 tables):

- Only `invitations.role` has a database allow-list (`role IN ('Admin', 'Analyst', 'Viewer')`). The other 22 do not.
- **Every column reads case-insensitively.** EF turns the stored text into the enum with a case-insensitive parse, so
  `owner`, `OWNER` and `Owner` are all read as `Owner`.
- **Every column throws on an unknown value.** One row holding `Bogus` makes every query that materializes that table
  fail until the row is fixed.
- **Existing check constraints compare exact case.** For example `ck_evidence_email_root_only` tests
  `method <> 'AdminEmail'`, so a row whose method is the text `adminemail` passes it and is still read as `AdminEmail`.

Nothing in the application writes such values (every write goes through the enum), so these are risks for anything that
writes to the database directly: a script, a restore, a bug, a future writer.

## Columns

Priority 1: the value decides authority, a gate decision, or scan eligibility.

| Column | Enum |
|---|---|
| `memberships.role` | MembershipRole |
| `users.status` | UserStatus |
| `organizations.status` | OrganizationStatus |
| `domains.status` | DomainStatus |
| `authorization_grants.status` | GrantStatus |
| `verification_evidence.method` | VerificationMethod |
| `verification_evidence.status` | EvidenceStatus |
| `verification_evidence.scope_ceiling_type` | ScopeCeilingType |
| `verification_evidence.assurance` | AssuranceLevel |
| `policy_decisions.outcome` | DecisionOutcome |
| `scan_runs.status` | ScanRunStatus |
| `scope_rules.rule_type` | ScopeRuleType |

Priority 2: history and workflow records.

| Column | Enum |
|---|---|
| `authorization_grants.grant_type` | GrantType |
| `domain_disputes.status` | DisputeStatus |
| `invitations.status` | InvitationStatus |
| `policy_decisions.trigger` | DecisionTrigger |
| `scan_run_authorization_checks.outcome` | CheckOutcome |
| `verification_attempts.result` | AttemptResult |
| `verification_challenges.method` | VerificationMethod |
| `verification_challenges.status` | ChallengeStatus |
| `verification_checks.outcome` | CheckOutcome |
| `verification_checks.triggered_by` | CheckTrigger |

Already covered: `invitations.role` (allow-list of the three invitable roles, plus a trigger that freezes it).

## Planned fix (not done)

One migration adding an allow-list check per column, **generated from the enum names** by a configuration helper so the
list cannot drift from the enum, plus a test that walks the model and fails when an enum-backed column has no allow-list.
Adding an enum member then needs a migration, which is the safe default. Adding the constraints validates existing rows,
and existing rows were all written through the enum.
