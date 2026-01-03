<#
.SYNOPSIS
    Gets current permissions and roles from Microsoft 365 and Azure services.

.DESCRIPTION
    This function retrieves the actual permissions, roles, and capabilities from various Microsoft 365 and Azure services
    to enable permission-based test execution decisions. Returns structured permission objects for each service.

.EXAMPLE
    Get-MtPermissions

.EXAMPLE
    $permissions = Get-MtPermissions
    $permissions.GraphApplication.Permissions -contains "Application.Read.All"

.LINK
    https://maester.dev/docs/commands/Get-MtPermissions
#>
function Get-MtPermissions {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        Write-Verbose "Retrieving permissions from all connected services..."

        Get-MtGraphPermissions
        Get-MtEntraRoleActions
        Get-MtExchangeRoles

        Write-Verbose "Permission retrieval completed successfully"
        return
    }
    catch {
        Write-Warning "Error retrieving permissions: $($_.Exception.Message)"
        return $null
    }
}
