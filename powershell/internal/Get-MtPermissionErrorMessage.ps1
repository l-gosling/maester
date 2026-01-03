<#
.SYNOPSIS
    Generates an error message based on the needed permissions.

.DESCRIPTION
    This function creates a human-readable error message based on the permission types
    and specific permissions that are required for a test.

.EXAMPLE
    $neededPermissions = @{
        ExchangeRoles = @("View-Only Configuration", "Role Management")
    }
    Get-MtPermissionErrorMessage -NeededPermissions $neededPermissions

    Returns an error message indicating the required Exchange roles.

.EXAMPLE
    $neededPermissions = @{
        GraphScopes = @("User.Read.All", "Directory.Read.All")
    }
    Get-MtPermissionErrorMessage -NeededPermissions $neededPermissions

    Returns an error message indicating the required Graph API scopes.
#>

function Get-MtPermissionErrorMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The needed permissions object from the test settings.
        [Parameter(Mandatory = $true)]
        [object]$NeededPermissions
    )

    $messages = @()

    # Handle ExchangeRoles
    if ($NeededPermissions.ExchangeRoles) {
        $roles = $NeededPermissions.ExchangeRoles -join "', '"
        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $messages += "Entra ID role 'Global Reader' or one of the Exchange roles ('$roles') must be granted to your account"
        } else {
            $messages += "Exchange role ('$roles') must be granted to service principal with app id '$($__MtSession.Identity.ApplicationId)'"
        }
    }

    # Handle GraphScopes
    if ($NeededPermissions.GraphScopes) {
        $scopes = $NeededPermissions.GraphScopes -join "', '"
        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $messages += "Graph API scope ('$scopes') must be consented to your account"
        } else {
            $messages += "Graph API scope ('$scopes') must be granted to service principal with app id '$($__MtSession.Identity.ApplicationId)'"
        }
    }

    # Handle EntraRoles
    if ($NeededPermissions.EntraRoles) {
        $roles = $NeededPermissions.EntraRoles -join "', '"
        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $messages += "Entra ID role ('$roles') must be assigned to your account"
        } else {
            $messages += "Entra ID role ('$roles') must be assigned to service principal with app id '$($__MtSession.Identity.ApplicationId)'"
        }
    }

    # Handle TeamsRoles
    if ($NeededPermissions.TeamsRoles) {
        $roles = $NeededPermissions.TeamsRoles -join "', '"
        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $messages += "Teams admin role ('$roles') must be assigned to your account"
        } else {
            $messages += "Teams admin role ('$roles') must be assigned to service principal with app id '$($__MtSession.Identity.ApplicationId)'"
        }
    }

    # Handle AzureRoles
    if ($NeededPermissions.AzureRoles) {
        $roles = $NeededPermissions.AzureRoles -join "', '"
        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $messages += "Azure role ('$roles') must be assigned to your account"
        } else {
            $messages += "Azure role ('$roles') must be assigned to service principal with app id '$($__MtSession.Identity.ApplicationId)'"
        }
    }

    if ($messages.Count -eq 0) {
        return "Required permissions are not configured or not met"
    }

    return $messages -join "; "
}
