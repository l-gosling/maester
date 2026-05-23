# Instructions

Based on the test information and the PowerShell code provided below, determine:
1. The **Severity** level (Critical, High, Medium, Low, Info).
2. The **RequiredPermissions** needed to run this test across different services.

Output your response ONLY as a valid JSON object with the following keys: `Severity`, `RequiredPermissions`. 
Do not include markdown fences or any other text.

Example output:
{
  "Severity": "High",
  "RequiredPermissions": {
    "Graph": ["Policy.Read.All", "User.Read.All"],
    "EntraRoles": ["Global Reader"],
    "ExchangeOnline": ["View-Only Configuration"],
    "Azure": ["Reader"]
  }
}

---
testInfo.json
%TEST_INFO_JSON%

---
PowerShell Code
%TEST_CODE%

---

## Permission Mapping Rules

Analyze the PowerShell code to identify which APIs and services are being called. 

### Microsoft Graph (Graph)
- **Automatic Scopes**: Identify the API endpoints used in `Invoke-MtGraphRequest -RelativeUri`.
  - `/policies/conditionalAccessPolicies` -> `Policy.Read.ConditionalAccess` or `Policy.Read.All`
  - `/users` -> `User.Read.All` or `Directory.Read.All`
  - `/applications` -> `Application.Read.All`
  - `/groups` -> `Group.Read.All`
  - `/directoryRoles` -> `RoleManagement.Read.Directory`
  - `/identity/conditionalAccess/policies` -> `Policy.Read.ConditionalAccess`
  - `/reports/azureADPremiumLicenseInsight` -> `Organization.Read.All`
  - `/reports/authenticationMethods/userRegistrationDetails` -> `UserAuthenticationMethod.Read.All`
- **Preference**: Always prefer `.Read` permissions over `.ReadWrite` unless the code is performing a POST/PATCH/DELETE.
- **Minimum Essential**: If the test only reads basic user info, `User.Read` is sufficient.

### Entra ID Directory Roles (EntraRoles)
- Most Maester tests require a directory role to read tenant-wide configuration. 
- **Recommendation**:
  - `Global Reader`: The most common requirement for reading any security configuration.
  - `Security Reader`: Preferred for security-specific logs or Defender data.
  - `Directory Readers`: For basic object lookups.
  - `Conditional Access Administrator`: For tests specifically analyzing CA policies.
  - `Global Administrator`: ONLY if the API documentation explicitly states no other role works.

### Exchange Online (ExchangeOnline)
- Identify required Management Roles based on the cmdlets used in `Get-MtExo` or `-Request`:
  - `View-Only Configuration`: For reading tenant settings, transport rules, etc.
  - `Security Reader`: For security-related exchange settings.
  - `View-Only Recipients`: For reading mailbox or recipient data.

### Azure RBAC (Azure)
- Identify the required Azure role for the resources queried:
  - `Reader`: Standard for reading resource configurations.
  - `Security Reader`: For security-specific resource data.

---

## Severity Levels

Every Maester test includes a severity level based on the CVSS score.

- **Critical (9.0 - 10.0)**: Direct admin access, full data compromise, straightforward exploitation.
- **High (7.0 - 8.9)**: Elevated privileges, significant data loss, difficult to exploit but high impact.
- **Medium (4.0 - 6.9)**: Requires social engineering, limited access, or specific network conditions.
- **Low (0.1 - 3.9)**: Little impact, requires local/physical access.
- **Info (0)**: Non-security settings or good practices.

## Other IMPORTANT Considerations
- Privilege escalation risk = High.
- Privileged access involvement (Admin roles) = High.
- Data loss/exposure risk = Medium or higher.
- Good practice but not a vulnerability = Low.
- Informational only = Info.
