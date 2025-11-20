# PowerShell Security Automation with Microsoft Security Services

 practical information to help you build PowerShell security automation using Microsoft tools. This covers everything from initial setup to real-world automation examples for major Microsoft security services.

Here is a practical, step-by-step guide to get you started.

### 🔐 Connect to Microsoft Security Services
To automate anything, you first need to connect. Here are the fundamental connection commands for key services.

| **Security Service** | **Primary Connection Cmdlet** | **Basic Authentication Command Example** |
| :--- | :--- | :--- |
| **Security & Compliance** | `Connect-IPPSSession` | `Connect-IPPSSession -UserPrincipalName "youradmin@contoso.com"` |
| **Defender for Endpoint** | Custom Authentication | Uses app credentials to get a token. |
| **Microsoft Sentinel** | `Connect-AzAccount` | Used implicitly when running scripts with the `Az` module. |

#### Detailed Connection Examples
*   **Security & Compliance PowerShell**: This is used for automating tasks related to data loss prevention, retention, insider risk, and more. The connection process is straightforward for standard Microsoft 365 environments.
    ```powershell
    # Example for Microsoft 365 GCC High
    Connect-IPPSSession -UserPrincipalName "chris@govt.us" -ConnectionUri "https://ps.compliance.protection.office365.us/powershell-liveid/" -AzureADAuthorizationEndpointUri "https://login.microsoftonline.us/common"
    ```
    After completing your tasks, always disconnect: `Disconnect-ExchangeOnline`.

*   **Defender for Endpoint APIs**: Automation here involves using an Azure AD app to get an access token, then using that token to interact with the API.
    ```powershell
    # Define your app and tenant details
    $tenantId = '00000000-0000-0000-0000-000000000000'
    $appId = '11111111-1111-1111-1111-111111111111'
    $appSecret = '22222222-2222-2222-2222-222222222222'
    
    # Get an OAuth token
    $resourceAppIdUri = 'https://securitycenter.onmicrosoft.com/windowsatpservice'
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $authBody = @{
        resource = "$resourceAppIdUri"
        client_id = "$appId"
        client_secret = "$appSecret"
        grant_type = 'client_credentials'
    }
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody
    $accessToken = $authResponse.access_token
    
    # Use the token to make API calls, e.g., to list alerts
    $alertUrl = "https://api.securitycenter.microsoft.com/api/alerts?`$top=10"
    $headers = @{ 
        'Authorization' = "Bearer $accessToken"
        'Content-Type' = 'application/json'
    }
    $alerts = (Invoke-RestMethod -Uri $alertUrl -Headers $headers).value
    ```

### ⚙️ Real-World Security Automation Examples
Here are practical scripts that combine these tools to solve common security operations tasks.

#### 1. Automate Microsoft Sentinel Content Updates
Keeping analytics rules and workbooks updated is crucial. This PowerShell script automates updating all default Microsoft Sentinel Analytics Rules, preserving your custom entity mappings.
```powershell
# This is a conceptual example. The full script is more extensive.
# Authenticate to Azure first, likely using Connect-AzAccount
 
# Get all enabled analytics rules that have a template
$rules = Get-AzSentinelAlertRule -ResourceGroupName "YourResourceGroup" -WorkspaceName "YourWorkspace" | Where-Object { $_.IsEnabled -and $_.TemplateName }
 
foreach ($rule in $rules) {
    # Check if a newer version of the rule template is available
    $latestTemplate = Get-AzSentinelAlertRuleTemplate | Where-Object { $_.Name -eq $rule.TemplateName -and $_.Version -gt $rule.TemplateVersion }
    
    if ($latestTemplate) {
        # Update the rule with the latest template, preserving customizations
        Update-AzSentinelAlertRule -ResourceGroupName $rule.ResourceGroupName -WorkspaceName $rule.WorkspaceName -RuleId $rule.Name -TemplateVersion $latestTemplate.Version
    }
}
```
A full toolkit with additional scripts for updating **Content Hub solutions** and **Workbooks** is available from Microsoft MVPs.

#### 2. Investigate Alerts by Correlating with Network Data
This script uses the Defender for Endpoint API to find machines with high-priority alerts and checks if they have connected to a known suspicious URL, providing crucial context for investigation.
```powershell
# ... (After obtaining the $accessToken and $alerts as shown in the connection section above)
 
$machinesToInvestigate = @()
 
foreach($alert in $alerts) {
    $isSevereAlert = $alert.severity -in 'Medium', 'High'
    $isOpenAlert = $alert.status -in 'InProgress', 'New'
    
    if($isOpenAlert -and $isSevereAlert) {
        if ($alert.machineId -notin $machinesToInvestigate) {
            $machinesToInvestigate += $alert.machineId
        }
    }
}
 
# If we found machines, run an advanced query to check their network connections
if ($machinesToInvestigate) {
    $commaSeparatedMachines = '"{0}"' -f ($machinesToInvestigate -join '","')
    $suspiciousUrl = "www.suspiciousUrl.com"
    
    $query = @"
        NetworkCommunicationEvents
        | where MachineId in ($commaSeparatedMachines)
        | where RemoteUrl == `"$suspiciousUrl`"
        | summarize ConnectionsCount = count() by MachineId
"@
    
    $queryUrl = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
    $queryBody = @{ 'Query' = $query } | ConvertTo-Json
    $queryHeaders = @{ 'Authorization' = "Bearer $accessToken"; 'Content-Type' = 'application/json' }
    
    $investigationResults = (Invoke-RestMethod -Method Post -Uri $queryUrl -Headers $queryHeaders -Body $queryBody).Results
    $investigationResults
}
```

### 🛡️ PowerShell Security Fundamentals
Before diving deep, ensure your scripting environment is secure:
*   **Execution Policy**: Set a policy (e.g., `RemoteSigned`) to control script execution.
*   **Script Block Logging**: Enable this logging to record script contents for auditing and security analysis.
*   **Constrained Language Mode**: This mode restricts access to potentially dangerous .NET types and can be enforced via system-wide application control policies.

### 💡 Advanced Automation and Orchestration
To build true end-to-end automation, consider these patterns:
*   **Use Azure Automation**: For running these scripts on a schedule, deploy them as runbooks in **Azure Automation**, which supports managed identities for secure authentication.
*   **Create Sentinel Playbooks**: Use **Azure Logic Apps** to create playbooks that can be triggered automatically by alerts or incidents in Microsoft Sentinel for orchestrated response.
*   **Manage Secrets with Key Vault**: Never store passwords or secrets in scripts. Use **Azure Key Vault** to securely retrieve credentials during execution.

I hope these practical examples provide a solid foundation for your PowerShell security automation projects. 

> BOLD: *Feel free to ask if you need more specific scripts or deeper dives into any of these areas!*

> If you are curious about more advanced scenarios automation using PowerShell with Microsoft security services see [here](4-Security-Automation-And-Engineering/Python-Security-automation.md).

I'll provide you with comprehensive PowerShell automation commands and examples specifically for IAM, Defender for Cloud, and Defender for Endpoint. Let me break this down into practical, real-world scenarios.

## 🔐 IAM (Azure AD) Security Automation

### 1. Connect to Azure AD and Microsoft Graph
```powershell
# Install required modules
Install-Module AzureAD -Force
Install-Module Microsoft.Graph -Force

# Connect to Azure AD (legacy)
Connect-AzureAD

# Connect to Microsoft Graph (modern)
Connect-MgGraph -Scopes @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All", 
    "RoleManagement.ReadWrite.Directory",
    "Policy.ReadWrite.ConditionalAccess"
)
```

### 2. User Account Security Automation
```powershell
# Find stale accounts (not logged in for 90 days)
$90DaysAgo = (Get-Date).AddDays(-90)
Get-MgUser -All | Where-Object {
    $_.SignInActivity.LastSignInDateTime -lt $90DaysAgo -and
    $_.AccountEnabled -eq $true
} | Select-Object DisplayName, UserPrincipalName, LastSignInDateTime

# Bulk disable and revoke licenses for inactive users
$InactiveUsers = Get-MgUser -Filter "signInActivity/lastSignInDateTime le $($90DaysAgo.ToString('yyyy-MM-dd'))" -All
foreach ($User in $InactiveUsers) {
    # Disable account
    Update-MgUser -UserId $User.Id -AccountEnabled:$false
    
    # Revoke all active sessions
    Revoke-MgUserSignInSession -UserId $User.Id
    
    Write-Output "Disabled and revoked sessions for: $($User.DisplayName)"
}
```

### 3. Privileged Identity Management Automation
```powershell
# Find users with Global Administrator role
$GlobalAdmins = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | 
    Get-MgDirectoryRoleMember | 
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }

$GlobalAdmins | ForEach-Object {
    [PSCustomObject]@{
        UserName = $_.AdditionalProperties.displayName
        UserPrincipalName = $_.AdditionalProperties.userPrincipalName
        Role = "Global Administrator"
    }
}

# Monitor for privileged role assignments over 30 days
$30DaysAgo = (Get-Date).AddDays(-30)
Get-MgDirectoryRole | ForEach-Object {
    $Role = $_
    Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id | ForEach-Object {
        if ($_.AdditionalProperties.createdDateTime -lt $30DaysAgo) {
            [PSCustomObject]@{
                Role = $Role.DisplayName
                User = $_.AdditionalProperties.displayName
                AssignmentDate = $_.AdditionalProperties.createdDateTime
                DaysAssigned = ((Get-Date) - [DateTime]$_.AdditionalProperties.createdDateTime).Days
            }
        }
    }
}
```

### 4. Conditional Access & MFA Security
```powershell
# Find users without MFA registered
Get-MgUser -All | Where-Object {
    $_.AccountEnabled -eq $true -and
    $_.StrongAuthenticationRequirements.State -ne "Enabled" -and
    $_.StrongAuthenticationMethods -eq $null
} | Select-Object DisplayName, UserPrincipalName

# Export users with weak authentication methods
Get-MgUser -All | Where-Object { $_.AccountEnabled -eq $true } | ForEach-Object {
    $User = $_
    $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id
    
    $HasWeakMethods = $AuthMethods | Where-Object {
        $_.AdditionalProperties.'@odata.type' -in @(
            '#microsoft.graph.passwordAuthenticationMethod',
            '#microsoft.graph.phoneAuthenticationMethod'
        )
    }
    
    if ($HasWeakMethods) {
        [PSCustomObject]@{
            UserName = $User.DisplayName
            UPN = $User.UserPrincipalName
            WeakMethods = ($HasWeakMethods.AdditionalProperties.'@odata.type' -join ', ')
        }
    }
}
```

## 🛡️ Defender for Cloud Automation

### 1. Connect to Azure and Defender for Cloud
```powershell
# Connect to Azure
Connect-AzAccount

# Set context to specific subscription
Set-AzContext -SubscriptionId "your-subscription-id"

# Import Defender for Cloud module
Import-Module Az.Security
```

### 2. Security Assessment Automation
```powershell
# Get all security recommendations across subscriptions
$Subscriptions = Get-AzSubscription
$AllRecommendations = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id
    $Recommendations = Get-AzSecurityRecommendation
    
    foreach ($Rec in $Recommendations) {
        $AllRecommendations += [PSCustomObject]@{
            Subscription = $Sub.Name
            ResourceName = $Rec.ResourceName
            Recommendation = $Rec.RecommendationName
            Severity = $Rec.Severity
            State = $Rec.State
            ResourceGroup = $Rec.ResourceGroup
        }
    }
}

# Export high severity recommendations
$AllRecommendations | Where-Object { $_.Severity -eq "High" -and $_.State -ne "Resolved" } | 
    Export-Csv -Path "HighSeverityRecommendations.csv" -NoTypeInformation
```

### 3. Auto-Remediation Scripts
```powershell
# Auto-remediate storage accounts without secure transfer
$UnsecureStorageAccounts = Get-AzStorageAccount | Where-Object {
    $_.EnableHttpsTrafficOnly -eq $false
}

foreach ($StorageAccount in $UnsecureStorageAccounts) {
    try {
        Set-AzStorageAccount -ResourceGroupName $StorageAccount.ResourceGroupName `
            -Name $StorageAccount.StorageAccountName `
            -EnableHttpsTrafficOnly $true
        
        Write-Output "Remediated storage account: $($StorageAccount.StorageAccountName)"
        
        # Log the remediation
        $LogEntry = @{
            Timestamp = Get-Date
            Action = "EnableHttpsTrafficOnly"
            ResourceType = "StorageAccount"
            ResourceName = $StorageAccount.StorageAccountName
            ResourceGroup = $StorageAccount.ResourceGroupName
            Status = "Success"
        }
        $LogEntry | Export-Csv -Path "RemediationLog.csv" -Append -NoTypeInformation
    }
    catch {
        Write-Error "Failed to remediate $($StorageAccount.StorageAccountName): $_"
    }
}

# Enable Defender plans across all subscriptions
$DefenderPlans = @("VirtualMachines", "Storage", "SqlServers", "AppServices")

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id
    
    foreach ($Plan in $DefenderPlans) {
        try {
            Set-AzSecurityPricing -Name $Plan -PricingTier "Standard"
            Write-Output "Enabled $Plan for subscription: $($Sub.Name)"
        }
        catch {
            Write-Warning "Failed to enable $Plan for $($Sub.Name): $_"
        }
    }
}
```

### 4. Regulatory Compliance Monitoring
```powershell
# Get compliance status for all subscriptions
$ComplianceReport = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id
    $ComplianceData = Get-AzRegulatoryComplianceStandard
    
    foreach ($Standard in $ComplianceData) {
        $Controls = Get-AzRegulatoryComplianceControl -StandardName $Standard.Name
        
        foreach ($Control in $Controls) {
            $ComplianceReport += [PSCustomObject]@{
                Subscription = $Sub.Name
                Standard = $Standard.Name
                Control = $Control.Name
                State = $Control.State
                PassedCount = $Control.PassedAssessmentCount
                FailedCount = $Control.FailedAssessmentCount
                SkippedCount = $Control.SkippedAssessmentCount
            }
        }
    }
}

$ComplianceReport | Export-Csv -Path "ComplianceReport.csv" -NoTypeInformation
```

## 🔍 Defender for Endpoint Automation

### 1. API Authentication Setup
```powershell
# Define authentication parameters
$tenantId = "your-tenant-id"
$appId = "your-app-id" 
$appSecret = "your-app-secret"

# Get access token for Defender for Endpoint API
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"

$authBody = @{
    resource = $resourceAppIdUri
    client_id = $appId
    client_secret = $appSecret
    grant_type = 'client_credentials'
}

$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody
$accessToken = $authResponse.access_token

$headers = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type' = 'application/json'
}
```

### 2. Advanced Hunting and Alert Management
```powershell
# Run advanced hunting query to find suspicious processes
$query = @"
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe')
| where InitiatingProcessFileName !in~ ('explorer.exe', 'mmc.exe', 'services.exe')
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "Invoke-"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 100
"@

$queryBody = @{ 'Query' = $query } | ConvertTo-Json
$advancedHuntingUrl = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

$results = Invoke-RestMethod -Method Post -Uri $advancedHuntingUrl -Headers $headers -Body $queryBody
$results.Results | Export-Csv -Path "SuspiciousProcesses.csv" -NoTypeInformation

# Get high severity alerts from last 24 hours
$alertsUrl = "https://api.securitycenter.microsoft.com/api/alerts?`$filter=Severity eq 'High' and Status eq 'New'"
$highSeverityAlerts = (Invoke-RestMethod -Uri $alertsUrl -Headers $headers).value

# Auto-investigate high severity alerts
foreach ($alert in $highSeverityAlerts) {
    $investigateUrl = "https://api.securitycenter.microsoft.com/api/alerts/$($alert.id)/investigate"
    $investigateBody = @{ 'Type' = 'Manual' } | ConvertTo-Json
    
    try {
        Invoke-RestMethod -Method Post -Uri $investigateUrl -Headers $headers -Body $investigateBody
        Write-Output "Started investigation for alert: $($alert.title)"
    }
    catch {
        Write-Error "Failed to investigate alert $($alert.id): $_"
    }
}
```

### 3. Device Isolation and Remediation
```powershell
# Function to isolate device
function Invoke-DeviceIsolation {
    param($DeviceName, $IsolationType = "Full")
    
    $deviceId = (Get-MdeMachine -Filter "ComputerDnsName eq '$DeviceName'").Id
    
    if ($deviceId) {
        $isolateUrl = "https://api.securitycenter.microsoft.com/api/machines/$deviceId/isolate"
        $isolateBody = @{
            Comment = "Automated isolation due to security alert"
            IsolationType = $IsolationType
        } | ConvertTo-Json
        
        Invoke-RestMethod -Method Post -Uri $isolateUrl -Headers $headers -Body $isolateBody
        Write-Output "Isolated device: $DeviceName"
    } else {
        Write-Warning "Device not found: $DeviceName"
    }
}

# Function to collect investigation package
function Start-InvestigationPackage {
    param($DeviceName)
    
    $deviceId = (Get-MdeMachine -Filter "ComputerDnsName eq '$DeviceName'").Id
    
    if ($deviceId) {
        $packageUrl = "https://api.securitycenter.microsoft.com/api/machines/$deviceId/collectInvestigationPackage"
        $response = Invoke-RestMethod -Method Post -Uri $packageUrl -Headers $headers
        
        Write-Output "Started investigation package collection for: $DeviceName"
        Write-Output "Action ID: $($response.Id)"
    }
}

# Automated response workflow
$criticalAlerts = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/alerts?`$filter=Severity eq 'High'" -Headers $headers).value

foreach ($alert in $criticalAlerts) {
    # Isolate device for ransomware or persistence alerts
    if ($alert.Title -match "Ransomware" -or $alert.Title -match "Persistence") {
        Invoke-DeviceIsolation -DeviceName $alert.DeviceName
        Start-InvestigationPackage -DeviceName $alert.DeviceName
    }
}
```

### 4. Security Configuration Monitoring
```powershell
# Check devices with security controls disabled
$securityConfigQuery = @"
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2010", "scid-2011", "scid-2012")  # Example security controls
| where IsApplicable == 1 and IsCompliant == 0
| project DeviceName, ConfigurationId, ConfigurationCategory, RiskScore
"@

$configBody = @{ 'Query' = $securityConfigQuery } | ConvertTo-Json
$configResults = (Invoke-RestMethod -Method Post -Uri $advancedHuntingUrl -Headers $headers -Body $configBody).Results

# Generate compliance report
$configResults | Group-Object ConfigurationCategory | ForEach-Object {
    [PSCustomObject]@{
        SecurityControl = $_.Name
        NonCompliantDevices = $_.Count
        AverageRiskScore = [math]::Round(($_.Group.RiskScore | Measure-Object -Average).Average, 2)
    }
} | Export-Csv -Path "SecurityConfigCompliance.csv" -NoTypeInformation
```

## 🚀 Integrated Security Automation Workflow

### Complete Incident Response Automation
```powershell
# Main security automation workflow
function Start-SecurityIncidentResponse {
    param(
        [string]$AlertId,
        [string]$AutomationLevel = "SemiAuto"  # SemiAuto or FullAuto
    )
    
    # Get alert details
    $alert = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/alerts/$AlertId" -Headers $headers)
    
    Write-Output "Processing alert: $($alert.Title)"
    Write-Output "Severity: $($alert.Severity)"
    Write-Output "Device: $($alert.DeviceName)"
    
    # Semi-automated response
    if ($AutomationLevel -eq "SemiAuto") {
        # Isolate device for high severity
        if ($alert.Severity -eq "High") {
            $confirm = Read-Host "Isolate device $($alert.DeviceName)? (y/n)"
            if ($confirm -eq 'y') {
                Invoke-DeviceIsolation -DeviceName $alert.DeviceName
            }
        }
        
        # Collect investigation package
        $confirm = Read-Host "Collect investigation package? (y/n)"
        if ($confirm -eq 'y') {
            Start-InvestigationPackage -DeviceName $alert.DeviceName
        }
    }
    # Fully automated response
    elseif ($AutomationLevel -eq "FullAuto" -and $alert.Severity -eq "High") {
        Invoke-DeviceIsolation -DeviceName $alert.DeviceName
        Start-InvestigationPackage -DeviceName $alert.DeviceName
        
        # Create ticket in connected system (example)
        New-SecurityTicket -Alert $alert -Priority "Critical"
    }
    
    # Update alert status
    $updateBody = @{ Status = "InProgress" } | ConvertTo-Json
    Invoke-RestMethod -Method Patch -Uri "https://api.securitycenter.microsoft.com/api/alerts/$AlertId" -Headers $headers -Body $updateBody
}
```

### Scheduled Security Health Check
```powershell
# Daily security health check script
function Invoke-DailySecurityHealthCheck {
    Write-Output "Starting daily security health check..."
    
    # 1. Check IAM security
    Write-Output "`n=== IAM Security Check ==="
    $staleAccounts = Get-MgUser -Filter "signInActivity/lastSignInDateTime le $(Get-Date).AddDays(-90)" -All
    Write-Output "Stale accounts found: $($staleAccounts.Count)"
    
    # 2. Check Defender for Cloud compliance
    Write-Output "`n=== Defender for Cloud Check ==="
    $highRecommendations = Get-AzSecurityRecommendation | Where-Object { $_.Severity -eq "High" -and $_.State -ne "Resolved" }
    Write-Output "High severity recommendations: $($highRecommendations.Count)"
    
    # 3. Check Defender for Endpoint alerts
    Write-Output "`n=== Defender for Endpoint Check ==="
    $activeAlerts = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/alerts?`$filter=Status eq 'New'" -Headers $headers).value
    Write-Output "Active alerts: $($activeAlerts.Count)"
    
    # Generate report
    $report = [PSCustomObject]@{
        Date = Get-Date
        StaleAccounts = $staleAccounts.Count
        HighSeverityRecommendations = $highRecommendations.Count
        ActiveAlerts = $activeAlerts.Count
        OverallStatus = if ($staleAccounts.Count -eq 0 -and $highRecommendations.Count -eq 0 -and $activeAlerts.Count -eq 0) { "Healthy" } else { "Attention Required" }
    }
    
    $report | Export-Csv -Path "DailySecurityReport.csv" -Append -NoTypeInformation
    return $report
}

# Run the health check
$healthStatus = Invoke-DailySecurityHealthCheck
Write-Output "Daily health check completed: $($healthStatus.OverallStatus)"
```

## 📋 Prerequisites and Setup

### Required Modules Installation
```powershell
# Install all required modules
$Modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement", 
    "Microsoft.Graph.Identity.SignIns",
    "Az",
    "Az.Security",
    "MSOnline"
)

foreach ($Module in $Modules) {
    Install-Module -Name $Module -Force -AllowClobber
    Import-Module -Name $Module
}
```

### API Permissions Required
- **Microsoft Graph**: User.ReadWrite.All, Directory.ReadWrite.All, Policy.ReadWrite.ConditionalAccess
- **Azure**: SecurityReader, SecurityAdmin  
- **Defender for Endpoint**: AdvancedQuery.ReadWrite, Alert.ReadWrite, Machine.ReadWrite

This comprehensive automation framework covers real-world scenarios across IAM, Defender for Cloud, and Defender for Endpoint.


> Happy scripting and stay secure!  🚀
