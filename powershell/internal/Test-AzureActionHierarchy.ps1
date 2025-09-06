<#
.SYNOPSIS
    Tests if a user Azure RBAC permission covers a needed permission using hierarchical rules.

.DESCRIPTION
    This function checks if a user's Azure RBAC permission covers a needed permission by applying
    Azure's hierarchical permission model. It supports wildcard matching at any level of the
    permission path and handles complex patterns like Microsoft.*/storageAccounts/*/read.

.PARAMETER UserPermission
    The Azure RBAC permission that the user has.

.PARAMETER NeededPermission
    The Azure RBAC permission that is required.

.EXAMPLE
    Test-AzureActionHierarchy -UserPermission "Microsoft.Compute/*" -NeededPermission "Microsoft.Compute/virtualMachines/read"
    Returns $true because Microsoft.Compute/* covers all actions under Microsoft.Compute

.EXAMPLE
    Test-AzureActionHierarchy -UserPermission "Microsoft.*/read" -NeededPermission "Microsoft.Storage/storageAccounts/read"
    Returns $true because Microsoft.*/read covers read actions on all Microsoft resources

.NOTES
    This function implements Azure RBAC permission hierarchy rules where:
    - Exact matches are always valid
    - Wildcards (*) can appear at any position
    - Shorter paths with wildcards can cover longer specific paths
    - Multiple wildcards in a single permission are supported
#>
function Test-AzureActionHierarchy {
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

    # Handle full wildcard
    if ($UserPermission -eq "*") {
        return $true
    }

    # Split permissions into parts: ResourceProvider/ResourceType/SubResource.../Action
    $userParts = $UserPermission.Split('/')
    $neededParts = $NeededPermission.Split('/')

    # Check all possible wildcard patterns
    for ($i = 0; $i -lt $userParts.Length; $i++) {
        if ($userParts[$i] -eq "*") {
            # Found a wildcard at position i
            # Check if everything before the wildcard matches
            $beforeWildcardMatches = $true
            for ($j = 0; $j -lt $i; $j++) {
                if ($j -ge $neededParts.Length -or $userParts[$j] -ne $neededParts[$j]) {
                    $beforeWildcardMatches = $false
                    break
                }
            }

            if ($beforeWildcardMatches) {
                # If wildcard is at the end, it covers everything after
                if ($i -eq $userParts.Length - 1) {
                    return $true
                }

                # If there are more parts after wildcard, check if remaining parts match
                $remainingUserParts = $userParts[($i + 1)..($userParts.Length - 1)]
                $remainingNeededParts = $neededParts[($i + 1)..($neededParts.Length - 1)]

                if ($remainingUserParts.Length -eq $remainingNeededParts.Length) {
                    $remainingMatches = $true
                    for ($k = 0; $k -lt $remainingUserParts.Length; $k++) {
                        if ($remainingUserParts[$k] -ne $remainingNeededParts[$k] -and $remainingUserParts[$k] -ne "*") {
                            $remainingMatches = $false
                            break
                        }
                    }
                    if ($remainingMatches) {
                        return $true
                    }
                }
            }
        }
    }

    # Check for hierarchical coverage (shorter path with exact match)
    if ($userParts.Length -lt $neededParts.Length) {
        $pathMatches = $true
        for ($i = 0; $i -lt $userParts.Length - 1; $i++) {
            if ($userParts[$i] -ne $neededParts[$i]) {
                $pathMatches = $false
                break
            }
        }

        # Last part should be wildcard for hierarchical coverage
        if ($pathMatches -and $userParts[-1] -eq "*") {
            return $true
        }
    }

    return $false
}
