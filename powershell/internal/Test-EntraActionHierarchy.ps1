<#
.SYNOPSIS
    Tests if a user Entra ID permission covers a needed permission using hierarchical rules.

.DESCRIPTION
    This function checks if a user's Entra ID permission covers a needed permission by applying
    Entra's hierarchical permission model. It supports the four-part structure:
    service/resource/properties/tasks and understands privilege escalation patterns.

.PARAMETER UserPermission
    The Entra ID permission that the user has.

.PARAMETER NeededPermission
    The Entra ID permission that is required.

.EXAMPLE
    Test-EntraActionHierarchy -UserPermission "microsoft.directory/allEntities/allProperties/read" -NeededPermission "microsoft.directory/users/basic/read"
    Returns $true because allEntities covers users, allProperties covers basic properties

.EXAMPLE
    Test-EntraActionHierarchy -UserPermission "microsoft.directory/users/standard/allTasks" -NeededPermission "microsoft.directory/users/basic/read"
    Returns $true because standard includes basic properties and allTasks covers read

.NOTES
    This function implements Entra ID permission hierarchy rules where:
    - Service level must match exactly (no wildcards)
    - allEntities covers any specific resource type
    - allProperties > standard > basic (property hierarchy)
    - allTasks covers any specific task
    - Exact matches are always valid
#>
function Test-EntraActionHierarchy {
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

    # Split permissions into parts: service/resource/properties/tasks
    $userParts = $UserPermission.Split('/')
    $neededParts = $NeededPermission.Split('/')

    # Both permissions must have the same structure (4 parts for full permissions)
    if ($userParts.Length -ne 4 -or $neededParts.Length -ne 4) {
        # Handle legacy format or partial permissions
        if ($userParts.Length -le $neededParts.Length) {
            $partMatches = $true
            for ($i = 0; $i -lt $userParts.Length; $i++) {
                if ($userParts[$i] -ne $neededParts[$i]) {
                    $partMatches = $false
                    break
                }
            }
            if ($partMatches -and $userParts.Length -lt $neededParts.Length) {
                return $true
            }
        }
        return $false
    }

    $userService = $userParts[0]
    $userResource = $userParts[1]
    $userProperties = $userParts[2]
    $userTasks = $userParts[3]

    $neededService = $neededParts[0]
    $neededResource = $neededParts[1]
    $neededProperties = $neededParts[2]
    $neededTasks = $neededParts[3]

    # Service must match (no wildcards at service level in Entra)
    if ($userService -ne $neededService) {
        return $false
    }

    # Check resource hierarchy
    $resourceMatches = ($userResource -eq $neededResource) -or ($userResource -eq "allEntities")

    # Check properties hierarchy
    $propertiesMatches = $false
    if ($userProperties -eq $neededProperties) {
        $propertiesMatches = $true
    } elseif ($userProperties -eq "allProperties") {
        $propertiesMatches = $true
    } elseif ($userProperties -eq "standard" -and $neededProperties -eq "basic") {
        # Standard includes basic properties
        $propertiesMatches = $true
    }

    # Check tasks hierarchy
    $tasksMatches = $false
    if ($userTasks -eq $neededTasks) {
        $tasksMatches = $true
    } elseif ($userTasks -eq "allTasks") {
        $tasksMatches = $true
    }

    return $resourceMatches -and $propertiesMatches -and $tasksMatches
}
