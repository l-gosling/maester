---
title: Permissions
sidebar_position: 4
---

# Permission Handling

Maester includes a mechanism to gracefully skip tests if the connected session lacks the required API permissions or directory roles. This prevents tests from failing with unhelpful errors and provides a better user experience.

## How it works

1.  **Permission Gathering**: When `Invoke-Maester` starts, it automatically gathers the available Graph scopes and directory roles for the connected services (Graph, Exchange, Azure, Teams).
2.  **Test ID Mapping**: Every test ID in `maester-config.json` is mapped to its `RequiredPermissions`. This mapping is automatically generated and updated by an AI-assisted GitHub workflow whenever you add or modify a test.
3.  **Graceful Skip**: Each test helper function calls `Test-MtHasPermission` at the beginning. If the required permissions are missing, the test reports a `LimitedPermissions` status and skips.

## Bypassing Permission Checks

There are three ways to bypass permission checks if you know you have the necessary access but Maester is skipping the test.

### 1. Global Bypass via CLI

Use the `-SkipPermissionCheck` switch when running `Invoke-Maester`:

```powershell
Invoke-Maester -SkipPermissionCheck
```

### 2. Global Bypass via Configuration

Add the `SkipPermissionCheck` property to the `GlobalSettings` section in your custom `maester-config.json`:

```json
{
  "GlobalSettings": {
    "SkipPermissionCheck": true
  }
}
```

### 3. Per-Test Bypass via Configuration

Add the `SkipPermissionCheck` property to a specific test in the `TestSettings` section in your custom `maester-config.json`:

```json
{
  "TestSettings": [
    {
      "Id": "MT.1001",
      "SkipPermissionCheck": true
    }
  ]
}
```

## Manual Permission Updates

While the `RequiredPermissions` property is managed automatically for core Maester tests, you can also define it for your own custom tests in your local configuration:

```json
{
  "TestSettings": [
    {
      "Id": "CTS.1001",
      "RequiredPermissions": {
        "Graph": ["User.Read.All"],
        "EntraRoles": ["Global Reader"]
      }
    }
  ]
}
```

### Permission Logic

*   **Graph Scopes**: Treated as **AND** conditions. You must have all listed scopes (or their `ReadWrite` equivalents).
*   **Directory/RBAC Roles**: Treated as **OR** conditions. You must have at least one of the listed roles.
