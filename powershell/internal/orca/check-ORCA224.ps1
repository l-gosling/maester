# Generated on 04/16/2025 21:38:23 by .\build\orca\Update-OrcaTests.ps1

using module ".\orcaClass.psm1"

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '')]
param()


<#

224 - Check MDO Phishing Similar Users Safety Tips 

#>



class ORCA224 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA224()
    {
        $this.Control=224
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Similar Users Safety Tips"
        $this.PassText="Similar Users Safety Tips is enabled"
        $this.FailRecommendation="Enable Similar Users Safety Tips so that users can receive visible indication on incoming messages"
        $this.Importance="Microsoft Defender for Office 365 can show a warning tip to recipients in messages that might be from an impersonated user."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Microsoft 365 Defender Portal - Anti-phishing"="https://security.microsoft.com/antiphishing"
            "Recommended settings for EOP and Microsoft Defender for Office 365"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {


        ForEach($Policy in ($Config["AntiPhishPolicy"]))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableSimilarUsersSafetyTips = $($Policy.EnableSimilarUsersSafetyTips)

            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="EnableSimilarUsersSafetyTips"
            $ConfigObject.ConfigData=$EnableSimilarUsersSafetyTips
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableSimilarUsersSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")        
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                       
            }

            $this.AddConfig($ConfigObject)

        }

        # Fail if all policy state is disabled
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableSimilarUsersSafetyTips"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }             

    }

}
