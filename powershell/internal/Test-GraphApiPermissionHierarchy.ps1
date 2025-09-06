<#
.SYNOPSIS
    Tests if a user Microsoft Graph API permission covers a needed permission using hierarchical rules.

.DESCRIPTION
    This function checks if a user's Graph API permission covers a needed permission by applying
    Microsoft Graph's hierarchical permission model. It supports the three-part structure:
    Resource.Operation.Scope and understands privilege escalation patterns.

.PARAMETER UserPermission
    The Microsoft Graph API permission that the user has.

.PARAMETER NeededPermission
    The Microsoft Graph API permission that is required.

.EXAMPLE
    Test-GraphApiPermissionHierarchy -UserPermission "User.ReadWrite.All" -NeededPermission "User.Read.All"
    Returns $true because ReadWrite includes Read operations

.EXAMPLE
    Test-GraphApiPermissionHierarchy -UserPermission "Directory.Read.All" -NeededPermission "User.Read.All"
    Returns $true because Directory.Read.All covers all user read operations

.EXAMPLE
    Test-GraphApiPermissionHierarchy -UserPermission "Policy.Read.All" -NeededPermission "Policy.Read.ApplicationConfiguration"
    Returns $true because Policy.Read.All covers all policy read operations

.NOTES
    This function implements Microsoft Graph API permission hierarchy rules where:
    - ReadWrite operations cover Read operations
    - Broader resource types (Directory) cover specific resources (User, Group)
    - .All scopes cover specific sub-scopes
    - Exact matches are always valid
#>
function Test-GraphApiPermissionHierarchy {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPermission,

        [Parameter(Mandatory = $true)]
        [string]$NeededPermission
    )

    # Exact match
    if ($UserPermission -eq $NeededPermission) {
        return $true
    }

    # Split permissions into parts: Resource.Operation.Scope
    $userParts = $UserPermission.Split('.')
    $neededParts = $NeededPermission.Split('.')

    # Both permissions should have 3 parts for standard Graph permissions
    if ($userParts.Length -ne 3 -or $neededParts.Length -ne 3) {
        return $false
    }

    $userResource = $userParts[0]
    $userOperation = $userParts[1]
    $userScope = $userParts[2]

    $neededResource = $neededParts[0]
    $neededOperation = $neededParts[1]
    $neededScope = $neededParts[2]

    # Define resource hierarchy - broader resources that cover specific ones
    $resourceHierarchy = @{
        'Directory' = @('User', 'Group', 'Organization', 'Contact', 'Device', 'Application', 'ServicePrincipal')
        'Sites' = @('Files')
        'Policy' = @('Policy') # Policy.Read.All covers Policy.Read.ApplicationConfiguration
        'BitlockerKey' = @('BitlockerKey') # BitlockerKey.Read.All covers BitlockerKey.ReadBasic.All
        'User' = @('User')
        'Group' = @('Group')
        'Application' = @('Application')
        'Files' = @('Files')
    }

    # Define operation hierarchy - broader operations that cover specific ones
    $operationHierarchy = @{
        'ReadWrite' = @('Read', 'Write', 'ReadBasic', 'ReadWrite')
        'Read' = @('Read', 'ReadBasic')
        'Write' = @('Write')
        'Create' = @('Create')
        'Delete' = @('Delete')
        'Manage' = @('Read', 'Write', 'Create', 'Delete', 'ReadWrite', 'ReadBasic', 'Manage')
    }

    # Check if user resource covers needed resource
    $resourceMatches = $false
    if ($userResource -eq $neededResource) {
        $resourceMatches = $true
    } elseif ($resourceHierarchy.ContainsKey($userResource) -and 
              $resourceHierarchy[$userResource] -contains $neededResource) {
        $resourceMatches = $true
    }

    # Check if user operation covers needed operation
    $operationMatches = $false
    if ($userOperation -eq $neededOperation) {
        $operationMatches = $true
    } elseif ($operationHierarchy.ContainsKey($userOperation) -and 
              $operationHierarchy[$userOperation] -contains $neededOperation) {
        $operationMatches = $true
    }

    # Check scope hierarchy
    $scopeMatches = $false
    if ($userScope -eq $neededScope) {
        $scopeMatches = $true
    } elseif ($userScope -eq "All") {
        # .All scope covers most specific scopes
        $scopeMatches = $true
    } elseif ($userResource -eq $neededResource -and $userOperation -eq "Read" -and $neededOperation -eq "Read") {
        # Special case: Resource.Read.All covers Resource.Read.SpecificScope
        if ($userScope -eq "All") {
            $scopeMatches = $true
        }
    }

    # Special handling for specific Graph permission patterns
    if (-not ($resourceMatches -and $operationMatches -and $scopeMatches)) {
        # Handle special cases where the pattern doesn't fit the standard hierarchy
        
        # Policy.Read.All covers Policy.Read.ApplicationConfiguration
        if ($UserPermission -eq "Policy.Read.All" -and $NeededPermission -like "Policy.Read.*") {
            return $true
        }
        
        # Policy.ReadWrite.All covers any Policy permission
        if ($UserPermission -eq "Policy.ReadWrite.All" -and $NeededPermission -like "Policy.*") {
            return $true
        }
        
        # BitlockerKey.Read.All covers BitlockerKey.ReadBasic.All
        if ($UserPermission -eq "BitlockerKey.Read.All" -and $NeededPermission -eq "BitlockerKey.ReadBasic.All") {
            return $true
        }
        
        # Application.ReadWrite.OwnedBy covers Application.Read.All in some scenarios
        if ($UserPermission -eq "Application.ReadWrite.OwnedBy" -and $NeededPermission -eq "Application.Read.All") {
            return $true
        }
        
        # Directory permissions cover most resource-specific permissions
        if ($UserPermission -like "Directory.*" -and $NeededPermission -notlike "Directory.*") {
            $dirParts = $UserPermission.Split('.')
            if ($dirParts.Length -eq 3) {
                $dirOperation = $dirParts[1]
                $dirScope = $dirParts[2]
                
                # Directory.Read.All covers any Read operation with All scope
                if ($dirOperation -eq "Read" -and $dirScope -eq "All" -and 
                    $neededOperation -eq "Read" -and $neededScope -eq "All") {
                    return $true
                }
                
                # Directory.ReadWrite.All covers any ReadWrite or Read operation
                if ($dirOperation -eq "ReadWrite" -and $dirScope -eq "All" -and 
                    ($neededOperation -in @("Read", "ReadWrite", "ReadBasic")) -and $neededScope -eq "All") {
                    return $true
                }
            }
        }
    }

    return $resourceMatches -and $operationMatches -and $scopeMatches
}
