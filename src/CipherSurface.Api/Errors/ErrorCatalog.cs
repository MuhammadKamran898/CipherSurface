using System.Collections.Frozen;

namespace CipherSurface.Api.Errors;

/// <summary>
/// The single place that decides which HTTP status each ServiceException code gets. A code that is not listed here is
/// answered with a generic 500 and logged, never passed through, so adding a service error without deciding its
/// status is visible (and a test fails).
/// </summary>
public static class ErrorCatalog
{
    private static readonly FrozenDictionary<string, int> Statuses = new Dictionary<string, int>
    {
        // 400: the request itself is wrong
        ["AccountError"] = 400, ["AttestationRequired"] = 400, ["DomainInvalid"] = 400, ["DomainIsPublicSuffix"] = 400,
        ["EmailInvalid"] = 400, ["HostInvalid"] = 400, ["InvalidRuleType"] = 400, ["InvalidSchedule"] = 400,
        ["InvalidToken"] = 400, ["MethodNotSupported"] = 400, ["NoteRequired"] = 400, ["NoteTooLong"] = 400,
        ["OrganizationNameRequired"] = 400, ["OrganizationNameTooLong"] = 400, ["PatternInvalid"] = 400,
        ["PatternOutsideDomain"] = 400, ["ReasonRequired"] = 400, ["ReasonTooLong"] = 400, ["RecipientNotAllowed"] = 400,
        ["WeakPassword"] = 400,
        ["InvalidRole"] = 400, ["InvalidRequest"] = 400, ["InvalidOrganizationId"] = 400, ["OrganizationRequired"] = 400, ["CurrentPasswordIncorrect"] = 400,

        // 401: not authenticated
        ["InvalidCredentials"] = 401, ["InvalidRefreshToken"] = 401, ["Unauthorized"] = 401,

        // 403: authenticated but not allowed
        ["NotAllowed"] = 403, ["OrganizationSuspended"] = 403, ["AccountDisabled"] = 403, ["NoOrganization"] = 403, ["InvitationEmailMismatch"] = 403,
        ["SetupTokenInvalid"] = 403, ["Forbidden"] = 403,

        // 404
        ["NotFound"] = 404, ["SetupDisabled"] = 404, ["InvalidInvitation"] = 404,

        // 410: it existed, and is gone for good
        ["InvitationExpired"] = 410,

        // 405, 413, 415
        ["MethodNotAllowed"] = 405, ["PayloadTooLarge"] = 413, ["UnsupportedMediaType"] = 415,

        // 409: the request is fine but the current state does not allow it
        ["AlreadyActive"] = 409, ["AlreadySuspended"] = 409, ["Busy"] = 409, ["ChallengeExpired"] = 409, ["EmailTaken"] = 409, ["AccountExists"] = 409, ["AlreadyMember"] = 409,
        ["InvitationNoLongerValid"] = 409, ["InvitationNotPending"] = 409, ["TooManyInvitations"] = 409,
        ["ChallengeNotActive"] = 409, ["ClaimantHasNoValidProof"] = 409, ["DisputeNotOpen"] = 409, ["DomainExists"] = 409,
        ["DomainNotVerifiable"] = 409, ["NoActiveGrant"] = 409, ["RuleExists"] = 409, ["RuleRemoved"] = 409,
        ["RunNotQueued"] = 409, ["RunNotRunning"] = 409, ["SetupClosed"] = 409, ["StartDeadlineExpired"] = 409,
        ["TooManyRules"] = 409,

        // 429: slow down
        ["AccountLockedOut"] = 429, ["AttemptLimitReached"] = 429, ["RateLimited"] = 429,

        // 502: an outside service failed
        ["EmailSendFailed"] = 502
    }.ToFrozenDictionary();

    public static bool TryGetStatus(string code, out int status) => Statuses.TryGetValue(code, out status);

    public static IReadOnlyCollection<string> Codes => Statuses.Keys;

    /// <summary>The code used for a response that has only a status (a missing route, a rejected body, a failed limit).</summary>
    public static string CodeForStatus(int status) => status switch
    {
        400 => "InvalidRequest",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "NotFound",
        405 => "MethodNotAllowed",
        413 => "PayloadTooLarge",
        415 => "UnsupportedMediaType",
        429 => "RateLimited",
        _ => "InternalError"
    };
}
