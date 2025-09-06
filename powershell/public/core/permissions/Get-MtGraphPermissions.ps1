
function Get-MtGraphPermissions {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        if (-not (Test-MtConnection Graph)) {
            Write-Verbose "No microsoft graph connection found"
            return
        }

        # Get Microsoft Graph context informations
        $context = Get-MgContext

        # Get additional informations from context data
        $__MtSession.Identity.AuthType = $context.AuthType
        Write-Verbose "Authtype is '$($__MtSession.Identity.AuthType)'"

        $__MtSession.Identity.ApplicationId = $context.ClientId
        Write-Verbose "ApplicationId is '$($__MtSession.Identity.ApplicationId)'"

        $__MtSession.Permissions.GraphAPIPermissions = $context.Scopes
        Write-Verbose "Graph API permissions count is '$(($__MtSession.Permissions.GraphAPIPermissions).Count)'"

        if ($context.AuthType -eq 'Delegated') {
            $__MtSession.Identity.AccountName = $context.Account
            $__MtSession.Identity.AccountId = (Invoke-MtGraphRequest -RelativeUri "me").Id
        } elseif ($context.AuthType -eq 'AppOnly' -or $context.AuthType -eq 'ManagedIdentity' ) {
            $__MtSession.Identity.AccountName = $context.AppName
            $__MtSession.Identity.AccountId = (Invoke-MtGraphRequest -RelativeUri servicePrincipals -Filter "appId eq '$($context.ClientId)'").id
        }
        return
    }
    catch {
        Write-Verbose "Error getting Graph permissions: $($_.Exception.Message)"
        throw $_
    }
}
