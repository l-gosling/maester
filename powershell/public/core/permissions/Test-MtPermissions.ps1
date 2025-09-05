function Test-MtPermissions {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Checks if the current session is connected to the specified service
        [ValidateSet('GraphAPIPermissions', 'EntraAction', 'ExchangeRole')]
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$PermissionType,

        # Checks if the current session is connected to the specified service
        [Parameter(Position = 0, Mandatory = $true)]
        [string[]]$NeededPermission
    )

    process {
        #region GraphAPIPermissions
        if ($PermissionType -eq 'GraphAPIPermissions') {
            $hasPermission = $false
            if ($__MtSession.Permissions.GraphAPIPermissions) {
                foreach ($permission in $NeededPermission) {
                    if ($__MtSession.Permissions.GraphAPIPermissions -contains $permission) {
                        $hasPermission = $true
                        continue
                    }
                }
            }
            return $hasPermission
        }
        #endregion GraphAPIPermissions
        #region EntraAction
        #
        if ($PermissionType -eq 'EntraAction') {
            $hasPermission = $false
            if ($__MtSession.Permissions.Entra) {
                foreach ($permission in $NeededPermission) {
                    if ($__MtSession.Permissions.Entra -contains $permission) {
                        $hasPermission = $true
                        continue
                    }
                }
            }
            return $hasPermission
        }
        #endregion EntraAction
        #region ExchangeRole
        #https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo
        if ($PermissionType -eq 'ExchangeRole') {
            $hasPermission = $false
            if ($__MtSession.Permissions.ExchangeRole) {
                foreach ($permission in $NeededPermission) {
                    if ($__MtSession.Permissions.ExchangeRole -contains $permission) {
                        $hasPermission = $true
                        continue
                    }
                }
                #Here check if "Exchange.ManageAsApp" api is granted to the entra id app
            }
            return $hasPermission
        }
        #endregion ExchangeRole
    }
}
