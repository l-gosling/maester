
<#
.SYNOPSIS
    Gets Exchange Online role assignments for the current user or service principal.

.DESCRIPTION
    This function retrieves Exchange Online role assignments for the currently authenticated user or service principal.
    The function gets all assigned roles, including those directly assigned or inherited from Entra ID roles.

.EXAMPLE
    Get-MtExchangeRoles
    # Gets Exchange role assignments for the current authenticated context

.LINK
    https://maester.dev/docs/commands/Get-MtExchangeRoles
#>
function Get-MtExchangeRoles {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {

        if (-not (Test-MtConnection ExchangeOnline)) {
            Write-Verbose "No Exchange Online connection found"
            return
        }

        if ($__MtSession.Identity.AuthType -eq 'Delegated') {
            $currentUser = Get-User -Identity $__MtSession.Identity.AccountName
            if ($currentUser) {
                try {
                    $__MtSession.Permissions.ExchangeRoles = (Get-ManagementRoleAssignment -RoleAssignee $currentUser.DistinguishedName).Role | Select-Object -Unique
                } catch {
                    Write-Verbose "No role assignments found for user or insufficient permissions: $($_.Exception.Message)"
                    $__MtSession.Permissions.ExchangeRoles = @()
                    return
                }
                Write-Verbose "Exchange role count is '$(($__MtSession.Permissions.ExchangeRoles).Count)'"
            } else {
                Write-Verbose "Current user with id '$($__MtSession.Identity.AccountId)' not found"
            }
        } elseif ($__MtSession.Identity.AuthType -eq 'AppOnly' -or $__MtSession.Identity.AuthType -eq 'ManagedIdentity' ) {
                try {
                    $__MtSession.Permissions.ExchangeRoles = (Get-ManagementRoleAssignment -RoleAssignee $__MtSession.Identity.AccountId).Role | Select-Object -Unique
                    Write-Verbose "Exchange role count is '$(($__MtSession.Permissions.ExchangeRoles).Count)'"
                } catch {
                    Write-Verbose "No role assignments found for user or insufficient permissions: $($_.Exception.Message)"
                    $__MtSession.Permissions.ExchangeRoles = @()
                    return
                }
        }
        return
    }
    catch {
        Write-Verbose "Error getting Graph permissions: $($_.Exception.Message)"
        throw $_
    }
}
