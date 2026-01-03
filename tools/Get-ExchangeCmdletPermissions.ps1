<#
.SYNOPSIS
    Finds the required permissions (roles) to run Exchange Online cmdlets.

.DESCRIPTION
    This script helps identify the required Exchange Online roles/permissions for:
    - Plain Exchange Online cmdlets (e.g., Get-AcceptedDomain)
    - Get-MtExo wrapper commands used by Maester tests

    Based on Microsoft documentation:
    https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions

.EXAMPLE
    # Find permissions for a single cmdlet
    .\Get-ExchangeCmdletPermissions.ps1 -Cmdlet "Get-OrganizationConfig"

.EXAMPLE
    # Find permissions for a specific cmdlet with parameters
    .\Get-ExchangeCmdletPermissions.ps1 -Cmdlet "Get-Mailbox" -Parameters "Identity"

.EXAMPLE
    # Find permissions for a Get-MtExo request (e.g., OrganizationConfig)
    .\Get-ExchangeCmdletPermissions.ps1 -MtExoRequest "OrganizationConfig"

.EXAMPLE
    # Find permissions for multiple Get-MtExo requests
    .\Get-ExchangeCmdletPermissions.ps1 -MtExoRequest "OrganizationConfig", "RoleAssignmentPolicy"

.NOTES
    Requires connection to Exchange Online PowerShell
    Connect-ExchangeOnline

.LINK
    https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions
#>

[CmdletBinding(DefaultParameterSetName = 'SingleCmdlet')]
param(
    # The Exchange Online cmdlet to find permissions for
    [Parameter(ParameterSetName = 'SingleCmdlet', Position = 0)]
    [string]$Cmdlet,

    # Optional: Specific parameters to check
    [Parameter(ParameterSetName = 'SingleCmdlet')]
    [string[]]$Parameters,

    # Find permissions for specific Get-MtExo request(s)
    [Parameter(ParameterSetName = 'MtExo', Mandatory)]
    [string[]]$MtExoRequest,

    # Show detailed output including role assignments
    [Parameter()]
    [switch]$Detailed
)

function Get-MtExoCommands {
    <#
    .SYNOPSIS
        Extracts the $commands hashtable from Get-MtExo.ps1
    #>
    [CmdletBinding()]
    param()

    # Find the Get-MtExo.ps1 file relative to this script
    $scriptRoot = $PSScriptRoot
    $getMtExoPath = Join-Path -Path $scriptRoot -ChildPath "..\powershell\public\cisa\exchange\Get-MtExo.ps1"

    if (-not (Test-Path $getMtExoPath)) {
        # Try alternative path
        $getMtExoPath = Join-Path -Path $scriptRoot -ChildPath "..\powershell\public\cisa\exchange\Get-MtExo.ps1" -Resolve -ErrorAction SilentlyContinue
        if (-not $getMtExoPath) {
            # Search for it
            $getMtExoPath = Get-ChildItem -Path (Split-Path $scriptRoot -Parent) -Recurse -Filter "Get-MtExo.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        }
    }

    if (-not $getMtExoPath -or -not (Test-Path $getMtExoPath)) {
        Write-Error "Could not find Get-MtExo.ps1 file"
        return $null
    }

    Write-Verbose "Reading Get-MtExo.ps1 from: $getMtExoPath"

    # Read the file content
    $content = Get-Content -Path $getMtExoPath -Raw

    # Extract the $commands hashtable using regex
    $pattern = '\$commands\s*=\s*@\{([^}]+)\}'
    $match = [regex]::Match($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if (-not $match.Success) {
        Write-Error "Could not extract commands from Get-MtExo.ps1"
        return $null
    }

    # Parse the hashtable entries
    $commands = @{}
    $entries = $match.Groups[1].Value -split "`n"

    foreach ($entry in $entries) {
        $entry = $entry.Trim()
        if ($entry -match '^"([^"]+)"\s*=\s*"([^"]+)"') {
            $key = $matches[1]
            $value = $matches[2]
            $commands[$key] = $value
        }
    }

    return $commands
}

function Get-CmdletPermissions {
    <#
    .SYNOPSIS
        Gets the required permissions for a specific Exchange Online cmdlet
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CmdletName,

        [string[]]$CmdletParameters,

        [switch]$IncludeDetails
    )

    $result = [PSCustomObject]@{
        Cmdlet           = $CmdletName
        Parameters       = $CmdletParameters -join ', '
        Roles            = @()
        RoleGroups       = @()
        Error            = $null
        RoleAssignments  = @()
    }

    try {
        # Step 1: Get management roles that have access to the cmdlet
        $getRoleParams = @{
            Cmdlet = $CmdletName
        }
        if ($CmdletParameters) {
            $getRoleParams['CmdletParameters'] = $CmdletParameters
        }

        Write-Verbose "Finding roles for cmdlet: $CmdletName"
        $roles = Get-ManagementRole @getRoleParams -ErrorAction Stop

        if (-not $roles) {
            $result.Error = "No roles found for this cmdlet"
            return $result
        }

        $result.Roles = @($roles.Name)

        # Step 2: Get role assignments for each role
        $roleAssignments = @()
        foreach ($role in $roles) {
            $assignments = Get-ManagementRoleAssignment -Role $role.Name -Delegating $false -ErrorAction SilentlyContinue
            if ($assignments) {
                foreach ($assignment in $assignments) {
                    $roleAssignments += [PSCustomObject]@{
                        Role             = $assignment.Role
                        RoleAssigneeType = $assignment.RoleAssigneeType
                        RoleAssigneeName = $assignment.RoleAssigneeName
                    }
                }
            }
        }

        $result.RoleAssignments = $roleAssignments
        $result.RoleGroups = @($roleAssignments | Where-Object { $_.RoleAssigneeType -eq 'RoleGroup' } | Select-Object -ExpandProperty RoleAssigneeName -Unique)

    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Format-PermissionResults {
    <#
    .SYNOPSIS
        Formats the permission results for display
    #>
    param(
        [Parameter(Mandatory)]
        [object]$Results,

        [switch]$Detailed
    )

    # Collect all unique roles
    $allRoles = @($Results | Where-Object { -not $_.Error } | ForEach-Object { $_.Roles } | Select-Object -Unique | Sort-Object)

    Write-Host ""
    Write-Host "Assign one role:" -ForegroundColor White
    $allRoles | ForEach-Object { Write-Host "  • $_" -ForegroundColor Green }
    Write-Host ""
}

# Main execution

# Check for Exchange Online connection
try {
    $connectionInfo = Get-ConnectionInformation -ErrorAction Stop
    if (-not $connectionInfo) {
        throw "Not connected"
    }
}
catch {
    Write-Error "Not connected to Exchange Online. Please connect first using: Connect-ExchangeOnline"
    exit 1
}

$results = @()

if ($MtExoRequest) {
    # Extract commands from Get-MtExo.ps1
    $MtExoCommands = Get-MtExoCommands
    if (-not $MtExoCommands) {
        Write-Error "Could not load Get-MtExo commands"
        exit 1
    }

    foreach ($request in $MtExoRequest) {
        if ($MtExoCommands.ContainsKey($request)) {
            $cmdletName = $MtExoCommands[$request]
            $result = Get-CmdletPermissions -CmdletName $cmdletName -IncludeDetails:$Detailed
            $result | Add-Member -NotePropertyName "MtExoRequest" -NotePropertyValue $request
            $results += $result
        }
        else {
            Write-Error "Unknown MtExo request: $request. Available: $($MtExoCommands.Keys -join ', ')"
        }
    }
}
elseif ($Cmdlet) {
    $results += Get-CmdletPermissions -CmdletName $Cmdlet -CmdletParameters $Parameters -IncludeDetails:$Detailed
}
else {
    return $null
}

# Display results
Format-PermissionResults -Results $results -Detailed:$Detailed

# Return results for pipeline use
#return $results
