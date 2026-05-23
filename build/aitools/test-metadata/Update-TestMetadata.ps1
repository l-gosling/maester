# This script will read the tests in test-results.json and maester-config.json (if it exists)
# then determine the severity and required permissions of the test using the Gemini AI API.
# The test-results.json file is a copy of one of the latest runs of Invoke-Maester.

param(
    [switch]$Force
)

function Get-PromptResult($prompt) {
    $apiKey = $Env:GeminiApiKey
    if (-not $apiKey) {
        Write-Host "Gemini API key not found in environment variable. Set with the following command." -ForegroundColor Red
        Write-Host ">`$Env:GeminiApiKey = '<key>'" -ForegroundColor Red
        Write-Host "You can get a new key from https://ai.google.dev/gemini-api/docs/api-key"
        exit 1
    }
    
    # Using v1beta and the latest flash model alias as per docs
    $uri = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

    $Headers = @{
        "Content-Type"   = "application/json"
        "X-goog-api-key" = $apiKey
    }

    $Body = @{
        contents = @(
            @{
                parts = @(
                    @{
                        text = $prompt
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 5

    # Retry logic for 429 errors
    $maxRetries = 5
    $retryCount = 0
    $waitInterval = 10 # Seconds

    while ($retryCount -lt $maxRetries) {
        # Using Invoke-WebRequest -SkipHttpErrorCheck to prevent stream disposal issues
        $Response = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -Headers $Headers -SkipHttpErrorCheck -ErrorAction SilentlyContinue

        if ($null -eq $Response) {
            Write-Host "CRITICAL ERROR: No response received from API." -ForegroundColor Red
            exit 1
        }

        $statusCode = [int]$Response.StatusCode
        $content = $Response.Content

        if ($statusCode -eq 200) {
            $json = $content | ConvertFrom-Json
            return $json.candidates.content.parts.text
        }
        
        # Log error details
        Write-Host "`n*****************************************" -ForegroundColor Red
        Write-Host "API ERROR ENCOUNTERED" -ForegroundColor Red
        Write-Host "Status Code: $statusCode"
        if ($content) { Write-Host "Error Body: $content" }
        Write-Host "*****************************************\n" -ForegroundColor Red

        if ($statusCode -eq 429) {
            $retryCount++
            $sleepTime = $waitInterval * $retryCount
            Write-Host "Rate limit hit (429). This often means your DAILY limit (1,500 requests) or MINUTE limit (15 requests) is exhausted." -ForegroundColor Yellow
            Write-Host "Check your quota at: https://aistudio.google.com/app/plan" -ForegroundColor Cyan
            Write-Host "Retrying in $sleepTime seconds... (Attempt $retryCount/$maxRetries)" -ForegroundColor Yellow
            Start-Sleep -Seconds $sleepTime
        } else {
            # Stop immediately for 404, 403, 401, 400
            Write-Host "Non-retryable error ($statusCode). Terminating workflow." -ForegroundColor Red
            exit 1
        }
    }
    
    throw "Max retries exceeded for AI API call."
}

function Get-MtMaesterConfig($ConfigFilePath) {
    if (-not (Test-Path $ConfigFilePath)) {
        Write-Host "Maester config file not found at: $ConfigFilePath. Creating a new one." -ForegroundColor Yellow
        $maesterConfig = @{
            GlobalSettings = @{
                EmergencyAccessAccounts = @()
                DataverseEnvironmentUrl = ""
                SkipPermissionCheck = $false
            }
            TestSettings = @()
        }
    } else {
        Write-Host "Maester config file found at: $ConfigFilePath. Loading existing settings." -ForegroundColor Green
        $maesterConfig = Get-Content -Path $ConfigFilePath -Raw | ConvertFrom-Json
        
        # Ensure GlobalSettings exists
        if (-not $maesterConfig.GlobalSettings) {
            $maesterConfig | Add-Member -MemberType NoteProperty -Name "GlobalSettings" -Value @{
                EmergencyAccessAccounts = @()
                DataverseEnvironmentUrl = ""
                SkipPermissionCheck = $false
            }
        }
    }
    return $maesterConfig
}

function Set-MtMaesterConfig($ConfigFilePath, $MaesterConfig) {
    # Always sort TestSettings by Id
    $MaesterConfig.TestSettings = $MaesterConfig.TestSettings | Sort-Object Id
    # Convert the test settings array to JSON
    $maesterConfigJson = $MaesterConfig | ConvertTo-Json -Depth 10
    # Save the setting
    Set-Content -Path $ConfigFilePath -Value $maesterConfigJson -Force
}

function Get-TestFunctionCode($ScriptBlock) {
    # Heuristic: Find the first Test-Mt* or Get-Mt* function called in the script block
    if ($ScriptBlock -match '(Test-Mt|Get-Mt|Get-ORCA|Get-Az|Get-EXO)[a-zA-Z0-9]+') {
        $functionName = $Matches[0]
        Write-Host "Searching for code for: $functionName" -ForegroundColor Cyan
        
        # Search in powershell/public and powershell/internal relative to Repo Root
        # Note: script is in build/aitools/test-metadata/
        $file = Get-ChildItem -Path "$PSScriptRoot/../../../powershell" -Recurse -Filter "$functionName.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($file) {
            return Get-Content -Path $file.FullName -Raw
        }
    }
    return "# Code not found for this test.`n$ScriptBlock"
}

# Change to the script's directory context
$OriginalLocation = Get-Location
Set-Location $PSScriptRoot

try {
    # Read the test-results.json file
    $testResultsFilePath = "./test-results.json"
    if (-not (Test-Path $testResultsFilePath)) {
        Write-Error "test-results.json not found at $testResultsFilePath"
        exit 1
    }
    $testResults = Get-Content -Path $testResultsFilePath -Raw | ConvertFrom-Json

    $promptFilePath = "./prompt-severity.md"
    $promptTemplate = Get-Content -Path $promptFilePath -Raw | Out-String

    # Path to root tests folder
    $configPath = "../../../tests/maester-config.json"
    $maesterConfig = Get-MtMaesterConfig $configPath

    # Loop through each test result and create a test setting
    foreach ($testResult in $testResults.Tests) {

        # Skip if test already has both severity AND permissions (unless -Force is used)
        $existingSetting = $maesterConfig.TestSettings | Where-Object { $_.Id -eq $testResult.Id }
        
        if (-not $Force -and $existingSetting -and $existingSetting.Severity -and $existingSetting.RequiredPermissions) {
            # Write-Host "Test $($testResult.Id) already has metadata. Skipping." -ForegroundColor Yellow
            continue
        }

        # Find out the code of the test
        $testCode = Get-TestFunctionCode -ScriptBlock $testResult.ScriptBlock

        $testInfo = [PSCustomObject]@{
            Id          = $testResult.Id
            Title       = $testResult.Title
            Description = $testResult.ResultDetail.Description
        }
        $testInfoJson = $testInfo | ConvertTo-Json -Depth 5

        $prompt = $promptTemplate -replace "%TEST_INFO_JSON%", $testInfoJson
        $prompt = $prompt -replace "%TEST_CODE%", $testCode

        Write-Host "Processing $($testResult.Id): $($testResult.Title)" -ForegroundColor Green
        
        # Call the AI API with the prompt
        try {
            $aiResponse = Get-PromptResult -prompt $prompt
            # Write-Host "AI Response: $aiResponse" -ForegroundColor Blue
            
            # AI response should be pure JSON now
            $metadata = $aiResponse | ConvertFrom-Json
            
            if ($existingSetting) {
                # Dynamically add properties if they don't exist (prevents "property not found" errors)
                $props = @("Severity", "RequiredPermissions")
                foreach ($p in $props) {
                    if ($null -eq $existingSetting.PSObject.Properties[$p]) {
                        $existingSetting | Add-Member -MemberType NoteProperty -Name $p -Value $metadata.$p
                    } else {
                        $existingSetting.$p = $metadata.$p
                    }
                }
            } else {
                # Create a new test setting object
                $testSetting = [PSCustomObject]@{
                    Id                  = $testResult.Id
                    Title               = $testResult.Title
                    Severity            = $metadata.Severity
                    RequiredPermissions = $metadata.RequiredPermissions
                }
                $maesterConfig.TestSettings += $testSetting
            }

            # Save periodically
            Set-MtMaesterConfig -ConfigFilePath $configPath -MaesterConfig $maesterConfig
            Write-Host "Updated metadata for $($testResult.Id)" -ForegroundColor Cyan
        } catch {
            # Rethrow if it's a terminating error (handled in Get-PromptResult)
            if ($_.Exception.Message -match "Terminating") { throw $_ }
            Write-Warning "Failed to process $($testResult.Id): $($_.Exception.Message)"
        }
        
        # Rate limiting friendly - increase for free tier (15 RPM -> 4s min, use 6s for safety)
        Start-Sleep -Seconds 6
    }
} finally {
    Set-Location $OriginalLocation
}
