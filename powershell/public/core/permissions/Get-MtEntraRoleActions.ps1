
function Get-MtEntraRoleActions {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {

        if (-not (Test-MtConnection Graph)) {
            Write-Verbose "No microsoft graph connection found"
            return
        }

        # Get role assignments for current user that are not limited by administrativ units
        $userRoleAssignments = Invoke-MtGraphRequest -RelativeUri "roleManagement/directory/roleAssignments" -Filter "principalId eq '$($__MtSession.Identity.AccountId)' and directoryScopeId eq '/'"

        # Get role definitions for assigned roles only
        $assignedRoleIds = $userRoleAssignments.RoleDefinitionId
        $roleDefinitions = @()
        foreach ($roleId in $assignedRoleIds) {
            $roleDefinition = Invoke-MtGraphRequest -RelativeUri "roleManagement/directory/roleDefinitions/$roleId"
                $roleDefinitions += $roleDefinition.rolePermissions.allowedResourceActions
        }

        # Remove duplicates from roleDefinitions array
        $roleDefinitions = $roleDefinitions | Select-Object -Unique

        # Add permissions to script variable
        $__MtSession.Permissions.EntraAction = $roleDefinitions
        Write-Verbose "Entra role actions count is '$(($__MtSession.Permissions.EntraAction).Count)'"

        return
    }
    catch {
        Write-Verbose "Error getting Graph permissions: $($_.Exception.Message)"
        throw $_
    }
}
