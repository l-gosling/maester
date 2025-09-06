function Test-MtPermissions {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Checks if the current session is connected to the specified service
        [ValidateSet('GraphAPIPermissions', 'EntraActions', 'AzureActions', 'ExchangeRoles')]
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$PermissionType,

        # Defines whether at least one (any) or all permissions must be covered
        [ValidateSet('Any', 'All')]
        [Parameter(Position = 1)]
        [string]$RequirementType = 'Any',

        # Checks if the current session is connected to the specified service
        [Parameter(Position = 2, Mandatory = $true)]
        [string[]]$NeededPermissions
    )

    process {
        # Get the appropriate permissions collection based on PermissionType
        $permissionsCollection = switch ($PermissionType) {
            'GraphAPIPermissions' { $__MtSession.Permissions.GraphAPIPermissions }
            'EntraActions' { $__MtSession.Permissions.EntraActions }
            'AzureActions' { $__MtSession.Permissions.AzureActions }
            'ExchangeRoles' { $__MtSession.Permissions.ExchangeRoles }
        }

        # If no permissions collection exists, return false
        if (-not $permissionsCollection) {
            return $false
        }

        # Return true if asterisk is the value
        if ($permissionsCollection -eq "*") {
            return $true
        }

        # Check permissions based on RequirementType
        if ($RequirementType -eq 'All') {
            # Check if all permissions are present or covered
            foreach ($neededPermission in $NeededPermissions) {
                $permissionFound = $false

                foreach ($userPermission in $permissionsCollection) {
                    if ($PermissionType -eq 'AzureActions') {
                        if (Test-AzureActionHierarchy -UserPermission $userPermission -NeededPermission $neededPermission) {
                            $permissionFound = $true
                            break
                        }
                    } elseif ($PermissionType -eq 'EntraActions') {
                        if (Test-EntraActionHierarchy -UserPermission $userPermission -NeededPermission $neededPermission) {
                            $permissionFound = $true
                            break
                        }
                    } else {
                        # For other permission types, use exact matching
                        if ($userPermission -eq $neededPermission) {
                            $permissionFound = $true
                            break
                        }
                    }
                }

                if (-not $permissionFound) {
                    return $false
                }
            }
            return $true
        } else {
            # Check if any permission is present or covered (default behavior)
            foreach ($neededPermission in $NeededPermissions) {
                foreach ($userPermission in $permissionsCollection) {
                    if ($PermissionType -eq 'AzureActions') {
                        if (Test-AzureActionHierarchy -UserPermission $userPermission -NeededPermission $neededPermission) {
                            return $true
                        }
                    } elseif ($PermissionType -eq 'EntraActions') {
                        if (Test-EntraActionHierarchy -UserPermission $userPermission -NeededPermission $neededPermission) {
                            return $true
                        }
                    } else {
                        # For other permission types, use exact matching
                        if ($userPermission -eq $neededPermission) {
                            return $true
                        }
                    }
                }
            }
            return $false
        }
    }
}
