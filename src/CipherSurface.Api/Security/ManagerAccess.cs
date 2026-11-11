using CipherSurface.Data.Enums;
using CipherSurface.Services;

namespace CipherSurface.Api.Security;

/// <summary>
/// The first gate of every write endpoint: Owner or Admin of an active organization. The role comes from
/// OrganizationContext, which the framework read from the database for THIS request. It runs before the content of the
/// request is validated or acted on and before any deployment capability (such as email) is revealed, so the order is
/// always login, then organization, then role, then everything else. (A body that is not JSON at all is still refused by
/// the framework first, with a 400 or 415.) The services check the same rule again; this is the earlier, cheaper copy.
/// </summary>
public static class ManagerAccess
{
    public static void Require(OrganizationContext org)
    {
        if (org.Role is not (MembershipRole.Owner or MembershipRole.Admin))
            throw new ServiceException("NotAllowed", "Only an organization Owner or Admin can do this.");
        if (org.OrganizationStatus != OrganizationStatus.Active)
            throw new ServiceException("OrganizationSuspended", "This organization is suspended.");
    }
}
