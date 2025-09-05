
function Get-MtGraphPermissions {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        # Get Microsoft Graph context informations
        $context = Get-MgContext

        # Get additional informations from context data
        $__MtSession.Permissions.AuthType = $context.AuthType
        Write-Verbose "Authtype is '$($__MtSession.Permissions.AuthType)'"

        $__MtSession.Permissions.ApplicationId = $context.ClientId
        Write-Verbose "ApplicationId is '$($__MtSession.Permissions.ApplicationId)'"

        $__MtSession.Permissions.Scopes = $context.Scopes
        Write-Verbose "Scope count is '$(($__MtSession.Permissions.Scopes).Count)'"

        if ($context.AuthType -eq 'Delegated') {
            $__MtSession.Permissions.AccountName = $context.Account
            $__MtSession.Permissions.AccountId = (Invoke-MtGraphRequest -RelativeUri "me").Id
        } elseif ($context.AuthType -eq 'AppOnly' -or $context.AuthType -eq 'ManagedIdentity' ) {
            $__MtSession.Permissions.AccountName = $context.AppName
            $__MtSession.Permissions.AccountId = (Invoke-MtGraphRequest -RelativeUri servicePrincipals -Filter "appId eq '$($context.ClientId)'").id
        }
        return
    }
    catch {
        Write-Verbose "Error getting Graph permissions: $($_.Exception.Message)"
        throw $_
    }
}
