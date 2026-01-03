<#
.SYNOPSIS
    Finds the required Azure RBAC permissions (actions and roles) for Azure REST API requests.

.DESCRIPTION
    This script analyzes Azure REST API paths to determine:
    - The resource provider and operation
    - The required Azure RBAC action(s)
    - Which built-in roles contain those actions

.EXAMPLE
    # Find permissions for an Azure REST API path
    .\Get-AzureRbacPermissions.ps1 -Path "/providers/Microsoft.Management/managementGroups"

.EXAMPLE
    # Find permissions with HTTP method consideration
    .\Get-AzureRbacPermissions.ps1 -Path "/subscriptions/{id}/resourceGroups" -Method "POST"

.EXAMPLE
    # Find permissions for multiple paths
    .\Get-AzureRbacPermissions.ps1 -Path "/providers/Microsoft.Management/managementGroups", "/subscriptions"

.NOTES
    Requires connection to Azure
    Connect-AzAccount

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
#>

[CmdletBinding()]
param(
    # The Azure REST API path(s) to analyze
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Path,

    # The HTTP method (affects write vs read permissions)
    [Parameter(Mandatory = $false)]
    [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
    [string]$Method = 'GET'
)

function Get-ResourceProviderFromPath {
    <#
    .SYNOPSIS
        Extracts the resource provider and operation from an Azure REST API path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiPath,

        [string]$HttpMethod = 'GET'
    )

    # Remove query string and leading slash
    $ApiPath = ($ApiPath -split '\?')[0].TrimStart('/')

    # Parse the path
    $pathParts = $ApiPath -split '/'

    $result = @{
        Path = $ApiPath
        ResourceProvider = $null
        ResourceType = $null
        Operation = $null
        RequiredActions = @()
    }

    # Find the providers segment
    $providersIndex = [array]::IndexOf($pathParts, 'providers')

    if ($providersIndex -ge 0 -and $providersIndex + 1 -lt $pathParts.Count) {
        # Extract provider namespace (e.g., Microsoft.Management)
        $result.ResourceProvider = $pathParts[$providersIndex + 1]

        # Extract resource type (e.g., managementGroups)
        if ($providersIndex + 2 -lt $pathParts.Count) {
            $result.ResourceType = $pathParts[$providersIndex + 2]
        }
    }
    elseif ($pathParts[0] -eq 'subscriptions' -and $pathParts.Count -gt 1) {
        # Handle subscription-level operations
        $result.ResourceProvider = 'Microsoft.Resources'
        $result.ResourceType = 'subscriptions'
    }

    # Determine the operation based on HTTP method
    $operation = switch ($HttpMethod.ToUpper()) {
        'GET' { 'read' }
        'POST' { 'write' }
        'PUT' { 'write' }
        'PATCH' { 'write' }
        'DELETE' { 'delete' }
        default { 'read' }
    }
    $result.Operation = $operation

    # Build the required action(s)
    if ($result.ResourceProvider -and $result.ResourceType) {
        $baseAction = "$($result.ResourceProvider)/$($result.ResourceType)/$operation"
        $result.RequiredActions = @($baseAction)

        # Add alternative patterns
        if ($operation -ne 'read') {
            # Write/delete permissions often also require read
            $result.RequiredActions += "$($result.ResourceProvider)/$($result.ResourceType)/read"
        }

        # Add wildcard patterns that would match
        $result.RequiredActions += "$($result.ResourceProvider)/$($result.ResourceType)/*"
        $result.RequiredActions += "$($result.ResourceProvider)/*"
    }

    return $result
}

function Get-RolesForAction {
    <#
    .SYNOPSIS
        Finds Azure built-in roles that contain the specified action(s)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Actions
    )

    Write-Verbose "Searching for roles with actions: $($Actions -join ', ')"

    # Get all role definitions
    try {
        # Try to get the subscription context
        $context = Get-AzContext
        $subscriptionId = $context.Subscription.Id

        if ($subscriptionId) {
            # If we have a subscription, use it as scope
            Write-Verbose "Using subscription scope: $subscriptionId"
            $allRoles = Get-AzRoleDefinition -Scope "/subscriptions/$subscriptionId" -ErrorAction Stop
        }
        else {
            # No subscription context - try to list subscriptions and use the first one
            Write-Verbose "No subscription in context, attempting to list subscriptions..."
            $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue

            if ($subscriptions -and $subscriptions.Count -gt 0) {
                $firstSub = $subscriptions[0]
                Write-Verbose "Using first available subscription: $($firstSub.Name)"
                $allRoles = Get-AzRoleDefinition -Scope "/subscriptions/$($firstSub.Id)" -ErrorAction Stop
            }
            else {
                # Fallback: try without scope (requires appropriate permissions)
                Write-Verbose "No subscriptions found, trying without scope..."
                $allRoles = Get-AzRoleDefinition -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve role definitions: $_"
        return @()
    }

    $matchingRoles = @()

    foreach ($role in $allRoles) {
        $roleActions = @($role.Actions)
        $hasMatch = $false

        foreach ($action in $Actions) {
            # Check for exact match
            if ($roleActions -contains $action) {
                $hasMatch = $true
                break
            }

            # Check for wildcard match
            foreach ($roleAction in $roleActions) {
                if ($roleAction -eq '*') {
                    $hasMatch = $true
                    break
                }

                # Convert action pattern to regex
                $pattern = '^' + [regex]::Escape($roleAction).Replace('\*', '.*') + '$'
                if ($action -match $pattern) {
                    $hasMatch = $true
                    break
                }
            }

            if ($hasMatch) { break }
        }

        if ($hasMatch) {
            $matchingRoles += [PSCustomObject]@{
                RoleName = $role.Name
                RoleId = $role.Id
                IsCustom = $role.IsCustom
                Description = $role.Description
                Actions = $role.Actions
                Assignable = $role.AssignableScopes
            }
        }
    }

    return $matchingRoles
}

function Format-AzureRbacResults {
    <#
    .SYNOPSIS
        Formats the Azure RBAC permission results
    #>
    param(
        [Parameter(Mandatory)]
        [object[]]$Results
    )

    foreach ($result in $Results) {
        Write-Host ""
        Write-Host "Path: $($result.ApiPath)" -ForegroundColor Yellow

        if ($result.ResourceProvider) {
            Write-Host "  Resource Provider: $($result.ResourceProvider)" -ForegroundColor DarkGray
            Write-Host "  Resource Type: $($result.ResourceType)" -ForegroundColor DarkGray
            Write-Host "  Operation: $($result.Operation)" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Required Actions (any of these):" -ForegroundColor White
            $result.PrimaryActions | ForEach-Object { Write-Host "    • $_" -ForegroundColor Cyan }
        }
        else {
            Write-Host "  ⚠ Could not determine resource provider from path" -ForegroundColor Red
        }

        if ($result.Roles.Count -gt 0) {
            Write-Host ""
            Write-Host "  Roles with Access:" -ForegroundColor White
            $result.Roles | Sort-Object RoleName | ForEach-Object {
                $roleType = if ($_.IsCustom) { "[Custom]" } else { "[Built-in]" }
                Write-Host "    • $($_.RoleName) $roleType" -ForegroundColor Green
            }
        }
        else {
            Write-Host ""
            Write-Host "  ⚠ No roles found (may need specific scope or custom role)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
}

# Main execution

# Check for Azure connection
try {
    $context = Get-AzContext -ErrorAction Stop
    if (-not $context) {
        throw "Not connected"
    }
    Write-Verbose "Connected to Azure: $($context.Subscription.Name)"
}
catch {
    Write-Error "Not connected to Azure. Please connect first using: Connect-AzAccount"
    exit 1
}

$results = @()

foreach ($apiPath in $Path) {
    Write-Verbose "Analyzing path: $apiPath"

    # Parse the path to determine resource provider and action
    $pathInfo = Get-ResourceProviderFromPath -ApiPath $apiPath -HttpMethod $Method

    if (-not $pathInfo.ResourceProvider) {
        Write-Warning "Could not determine resource provider for path: $apiPath"
        continue
    }

    # Find roles that contain the required actions
    $roles = Get-RolesForAction -Actions $pathInfo.RequiredActions

    $results += [PSCustomObject]@{
        ApiPath = $apiPath
        ResourceProvider = $pathInfo.ResourceProvider
        ResourceType = $pathInfo.ResourceType
        Operation = $pathInfo.Operation
        PrimaryActions = @($pathInfo.RequiredActions[0], $pathInfo.RequiredActions[1]) | Where-Object { $_ }
        AllMatchingActions = $pathInfo.RequiredActions
        Roles = $roles
    }
}

# Display results
Format-AzureRbacResults -Results $results

# Return results for pipeline use
#return $results
