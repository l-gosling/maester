<#
.SYNOPSIS
    Gets all Azure RBAC role actions for the current principal.

.DESCRIPTION
    This function retrieves all Azure RBAC role actions for the current user or service principal
    from role assignments at the tenant root management group scope.
    https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

.EXAMPLE
    Get-AzureRbacRoles

.EXAMPLE
    Get-AzureRbacRoles
    # Check if specific action is available
    $__MtSession.Permissions.ExchangeRoles -contains "Microsoft.Authorization/roleAssignments/read"
#>
function Get-AzureRoleActions {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        if (-not (Test-MtConnection Azure)) {
            Write-Verbose "No Azure connection found"
            return
        }

        try {
            # Get all management groups in the tenant and filter the tenant root management group by id
            $rootManagementGroup = Get-MtAzureManagementGroup -ErrorAction Stop | Where-Object { $_.id -match "$($_.properties.tenantid)$" }

            # Get role assignments for all scopes
            $assignments = @()

            # Get role assigments for tenant root management group
            $roleAssignments = (Invoke-MtAzureRequest -RelativeUri "providers/Microsoft.Management/managementGroups/$($rootManagementGroup.name)/providers/Microsoft.Authorization/roleAssignments" -ApiVersion "2020-04-01-preview" -Filter "principalId eq '$($__MtSession.Identity.AccountId)'" | Select-Object -ExpandProperty value -ErrorAction Stop).properties

            # Get all actions for tenant root management group
            if ($roleAssignments) {
                foreach ($assignment in $roleAssignments) {
                    $roleDefResponse = Invoke-MtAzureRequest -RelativeUri "$($assignment.roleDefinitionId)" -ApiVersion "2022-04-01" -Filter "principalId eq '$($__MtSession.Identity.AccountId)'" | Select-Object -ExpandProperty properties
                    if ($roleDefResponse.permissions.actions -eq "*") {
                        $__MtSession.Permissions.AzureActions = $roleDefResponse.permissions.actions
                        Write-Verbose "Found all Azure RBAC role assignments for principal"
                        return
                    }else {
                        $assignments += $roleDefResponse.permissions.actions
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve role assignments for scope: $scope - $($_.Exception.Message)"
        }

        # Set session variable
        $__MtSession.Permissions.AzureActions = $assignments | Sort-Object -Unique
        Write-Verbose "Found $($roleAssignments.Count) Azure RBAC role assignments for principal"
        return
    }
    catch {
        Write-Verbose "Error getting Azure RBAC roles: $($_.Exception.Message)"
        return
    }
}
