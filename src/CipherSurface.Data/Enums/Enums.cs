namespace CipherSurface.Data.Enums;

// All enums are stored as strings (see CipherSurfaceDbContext) so that partial-index
// filters and check constraints stay readable in SQL.

public enum OrganizationStatus { Active, Suspended }
public enum UserStatus { Active, Disabled }
public enum MembershipRole { Owner, Admin, Analyst, Viewer }

public enum GrantType { SelfAttestation, MultiParty }
public enum GrantStatus { Active, Revoked }

public enum DomainStatus { Pending, Verified, AtRisk, Lapsed, Failed, Revoked, Disputed }
public enum DisputeStatus { Open, ResolvedIncumbent, ResolvedClaimant, Dismissed }

public enum VerificationMethod { DnsTxt, HttpFile, HtmlMeta, AdminEmail }
public enum ChallengeStatus { Issued, Checking, Passed, Failed, Expired, Superseded }
public enum AssuranceLevel { High, Medium, Low }
public enum ScopeCeilingType { DomainAndSubdomains, ExactHost, RootOnly }
public enum EvidenceStatus { Active, AtRisk, Lapsed, Expired, Revoked }

public enum CheckOutcome { ProofValid, ProofAbsent, Inconclusive }
public enum CheckTrigger { User, System }

public enum ScopeRuleType { Include, Exclude }
public enum DecisionTrigger { Manual, Scheduled }
public enum DecisionOutcome { Allow, Deny }

public enum ScanRunStatus { Queued, Running, CancelRequested, Cancelled, Completed, Failed }
public enum ContinuationOutcome { Continue, Restrict, Cancel }
