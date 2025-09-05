
function Get-MtExchangeRoles {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {

        if (-not (Test-MtConnection ExchangeOnline)) {
            Write-Verbose "No Exchange Online connection found"
            return
        }

        if ($__MtSession.Permissions.AuthType -eq 'Delegated') {
            $currentUser = Get-User -Identity $__MtSession.Permissions.AccountName
            if ($currentUser) {
                # Get role assignments for the current signed-in user
                $__MtSession.Permissions.ExchangeRole = (Get-ManagementRoleAssignment -RoleAssignee $currentUser.DistinguishedName).Role
                Write-Verbose "Exchange role count is '$(($__MtSession.Permissions.ExchangeRole).Count)'"
            } else {
                Write-Verbose "Current user with id '$($__MtSession.Permissions.AccountId)' not found"
            }
        } elseif ($__MtSession.Permissions.AuthType -eq 'AppOnly' -or $__MtSession.Permissions.AuthType -eq 'ManagedIdentity' ) {
            $servicePrincipal = Get-ServicePrincipal -Identity $__MtSession.Permissions.AccountId
            if ($servicePrincipal) {
                # Get role assignments
                $__MtSession.Permissions.ExchangeRole = (Get-ManagementRoleAssignment -RoleAssignee $servicePrincipal.ObjectId).Role
                Write-Verbose "Exchange role count is '$(($__MtSession.Permissions.ExchangeRole).Count)'"
            }else {
                Write-Verbose "Not service principal with object id '$($__MtSession.Permissions.AccountId)' found"
            }
        }
        return
    }
    catch {
        Write-Verbose "Error getting Graph permissions: $($_.Exception.Message)"
        throw $_
    }
}
