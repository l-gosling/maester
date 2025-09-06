function Test-MtPermissions {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Checks if the current session is connected to the specified service
        [ValidateSet('GraphAPIPermissions', 'EntraActions', 'ExchangeRoles')]
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$PermissionType,

        # Checks if the current session is connected to the specified service
        [Parameter(Position = 1, Mandatory = $true)]
        [string[]]$NeededPermission,

        # Defines whether at least one (any) or all permissions must be covered
        [ValidateSet('Any', 'All')]
        [Parameter(Position = 2)]
        [string]$RequirementType = 'Any'
    )

    process {
        # Get the appropriate permissions collection based on PermissionType
        $permissionsCollection = switch ($PermissionType) {
            'GraphAPIPermissions' { $__MtSession.Permissions.GraphAPIPermissions }
            'EntraActions' { $__MtSession.Permissions.Entra }
            'ExchangeRoles' { $__MtSession.Permissions.ExchangeRoles }
        }

        # If no permissions collection exists, return false
        if (-not $permissionsCollection) {
            return $false
        }

        # Check permissions based on RequirementType
        if ($RequirementType -eq 'All') {
            # Check if all permissions are present
            foreach ($permission in $NeededPermission) {
                if ($permissionsCollection -notcontains $permission) {
                    return $false
                }
            }
            return $true
        } else {
            # Check if any permission is present (default behavior)
            foreach ($permission in $NeededPermission) {
                if ($permissionsCollection -contains $permission) {
                    return $true
                }
            }
            return $false
        }
    }
}
