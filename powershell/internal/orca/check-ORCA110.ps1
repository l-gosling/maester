# Generated on 04/16/2025 21:38:23 by .\build\orca\Update-OrcaTests.ps1

using module ".\orcaClass.psm1"

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '')]
param()


<#

ORCA-110 Check if internal malware notification is disabled in malware policies.    

#>



class ORCA110 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA110()
    {
        $this.Control="ORCA-110"
        $this.Area="Malware Filter Policy"
        $this.Name="Internal Sender Notifications"
        $this.PassText="Internal Sender notifications are disabled"
        $this.FailRecommendation="Disable notifying internal senders of malware detection"
        $this.Importance="Notifying internal senders about malware detected in email messages could have negative impact. An adversary with access to an already compromised mailbox may use this information to verify effectiveness of malware detection."
        $this.ExpandResults=$True
        $this.ItemName="Malware Policy"
        $this.DataType="EnableInternalSenderAdminNotifications"
        $this.Links= @{
            "Microsoft 365 Defender Portal - Anti-malware"="https://security.microsoft.com/antimalwarev2"
            "Recommended settings for EOP and Office 365 Microsoft Defender for Office 365 security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["MalwareFilterPolicy"]).Count
        $CountOfPolicies = ($global:MalwarePolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableInternalSenderNotifications = $($Policy.EnableInternalSenderAdminNotifications)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$EnableInternalSenderNotifications
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If ($EnableInternalSenderNotifications -eq $False)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)
        }
    }

}
