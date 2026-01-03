<#
.SYNOPSIS
    Gets the test ID from the current Pester test context.

.DESCRIPTION
    This function extracts the test ID (e.g., 'MT.1041', 'CISA.MS.AAD.1.1') from the current
    Pester test context. It looks for tags that match common test ID patterns.

.EXAMPLE
    $testId = Get-MtPesterTestId

    Returns the test ID like 'MT.1041' from the current Pester test.

.NOTES
    The test ID is typically the first tag in the Pester test that matches the pattern
    for Maester test IDs (e.g., MT.*, CISA.*, EIDSCA.*, CIS.*, ORCA.*).
#>

function Get-MtPesterTestId {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # Check if we're running in a Pester context
    if (-not $____Pester -or -not $____Pester.CurrentTest) {
        Write-Verbose "Not running in a Pester context."
        return $null
    }

    try {
        # Look for tags that match common test ID patterns
        # Test IDs typically start with MT., CISA., EIDSCA., CIS., ORCA. etc.
        $testIdPattern = '^(.*\.)'

        $testId = $____Pester.CurrentTest.Tag | Where-Object { $_ -match $testIdPattern } | Select-Object -First 1

        if ($testId) {
            Write-Verbose "Found test ID: $testId"
            return $testId
        }

        # Fallback: check the first tag as test ID (common convention)
        $firstTag = $____Pester.CurrentTest.Tag | Select-Object -First 1
        if ($firstTag -and $firstTag -match '^\w+\.\w+') {
            Write-Verbose "Using first tag as test ID: $firstTag"
            return $firstTag
        }
    }
    catch {
        Write-Verbose "Error getting test ID: $_"
    }

    return $null
}
