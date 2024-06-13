function Manage-ServiceWithTimeout2 {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$DisplayName,
        [int]$Timeout = 5,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stop-Service', 'Start-Service')]
        [string]$Mode,
        [string]$StartUpType
    )
    Process {
        $service = Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Host "Service with DisplayName '$DisplayName' not found." -ForegroundColor Yellow
            return
        }
        switch ($Mode) {
            'Stop-Service' {
                $job = Start-Job -ScriptBlock {
                    param($DisplayName)
                    Stop-Service -DisplayName $DisplayName -Force -Confirm:$false -ErrorAction SilentlyContinue -PassThru | Set-Service -StartupType Manual -PassThru -ErrorAction SilentlyContinue
                } -ArgumentList $DisplayName
            }
            'Start-Service' {
                $job = Start-Job -ScriptBlock {
                    param($DisplayName, $StartUpType)
                    Start-Service -DisplayName $DisplayName -Confirm:$false -ErrorAction SilentlyContinue -PassThru -Verbose | Set-Service -StartupType $StartUpType -PassThru -ErrorAction SilentlyContinue -Verbose
                } -ArgumentList $DisplayName, $StartUpType 
            }
        }
        $waitResult = $job | Wait-Job -Timeout $timeout -ErrorAction SilentlyContinue
        $result = $job | Receive-Job -Force -Wait -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
        if ($result) {
            return @{
                'Status'             = $result.Status
                'ServiceDisplayName' = $result.DisplayName
                'ServiceName'        = $result.Name
                'StartUpType'        = $service.StartUpType.ToString()       
            }
        }
        else {
            return @{
                'Status'             = "$mode job timed out."
                'ServiceDisplayName' = $service.DisplayName
                'ServiceName'        = $service.ServiceName
                'StartUpType'        = $service.StartUpType.ToString()
            }
        }
    }
}
function Manage-ServiceWithTimeout {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$DisplayName,
        [int]$Timeout = 5,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stop-Service', 'Start-Service')]
        [string]$Mode,
        [string]$StartUpType = 'Manual'
    )
    $service = Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Host "Service with DisplayName '$DisplayName' not found." -ForegroundColor Yellow
        return
    }
    $job = Start-Job -ScriptBlock {
        param($DisplayName, $StartUpType, $Mode)
        & $Mode -DisplayName $DisplayName -Confirm:$false -ErrorAction SilentlyContinue -PassThru -Verbose | Set-Service -StartupType $StartUpType -PassThru -ErrorAction SilentlyContinue -Verbose
    } -ArgumentList $DisplayName, $StartUpType, $Mode
    $job | Wait-Job -Timeout $timeout -ErrorAction SilentlyContinue
    $result = $job | Receive-Job -Force -Wait -ErrorAction SilentlyContinue
    Remove-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
    $output = @{
        'Status'             = if ($result) { $result.Status } else { "$mode job timed out." }
        'ServiceDisplayName' = $service.DisplayName
        'ServiceName'        = $service.ServiceName
        'StartUpType'        = $service.StartUpType.ToString()
    }
    return $output
}
function Toggle-GameMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable-GameMode', 'Disable-GameMode')]
        [string]$Mode,
        [string]$ConfigFile = "./ServicesConfig.xml",
        $ExcludedProcesses = @('plex media server', 'ROCCAT_Swarm_Monitor', 'pcee4', 'pcee4e', 'XtuService', 'TeamViewer', 'qbittorrent', 'Opera', 'code', 'pwsh', 'powershell', 'SVPManager'),
        [switch]$Turbo
    )
    if (-not (Test-Path $ConfigFile -PathType Leaf)) {
        @() | Export-Clixml -Path $ConfigFile
    }
    if ($turbo) {
        $excludedProcesses = @('code', 'pwsh') 
    }
    $whitelistedProcesses = @(
        'System', 'svchost', 'wininit', 'winlogon', 'services', 'csrss', 'conhost', 'dwm', 'explorer', 'smss', 'lsass', 'MsMpEng', 'ctfmon', 'WmiPrvSE', 'taskhostw', 'sihost', 'RuntimeBroker',
        'Registry', 'Idle', 'dasHost', 'StartMenuExperienceHost', 'TextInputHost', 'SearchHost', 'dllhost', 'fontdrvhost', 'lsaiso', 'SecHealthUI', 'SecurityHealthService', 'SgrmBroker', 'crashpad_handler',
        'ApplicationFrameHost', 'LsaIso', 'SecurityHealthHost', 'LockApp', 'SystemSettingsBroker', 'ShellExperienceHost', 'Secure System', 'audiodg', 'WMIADAP', 'Memory Compression', 'HotPatch', 'NisSrv', 'NVDisplay.Container'
    )
    $whitelistServices = @(
        'Background Tasks Infrastructure Service'  
    )
    $servicesToStop = @(
        "AppX Deployment Service (AppXSVC)", "AVCTP Service", "AllJoyn Router Service", "Background Intelligent Transfer Service", "BitLocker Drive Encryption Service",
        "Bluetooth User Support Service*", "BranchCache", "COM+ Event System", "COM+ System Application", "CaptureService*", "Cellular Time", "Certificate propagation", "Client License Service (ClipSVC)", "Connected Devices Platform Service",
        "Connected Devices Platform User Service*", "Connected User Experiences and Telemetry", "Contact Data*", "CredentialEnrollmentManagerUserSvc*", "Data Sharing Service", "Data Usage", "Device Association Service", "Device Association Broker*",
        "Device Management Enrollment Service", "Device Management Wireless Application Protocol (WAP) Push message Routing Service", "DevQuery Background Discovery Broker", "Diagnostic Execution Service", "Diagnostic Policy Service",
        "Diagnostic Service Host", "Diagnostic System Host", "Distributed Link Tracking Client", "Distributed Transaction Coordinator", "Downloaded Maps Manager", "Embedded Mode", "Enterprise App Management Service", "Energy Server Service queencreek",
        "FAX", "File History Service", "Function Discovery Provider Host", "Function Discovery Resource Publication", "GameDVR and Broadcast User Service*", "Geolocation Service", "Google Update Service (gupdatem)", "Google Update Service (gupdate)",
        "HV Host Service", "Hyper-V Guest Service Interface", "Hyper-V Guest Shutdown Service", "Hyper-V Heartbeat Service", "Hyper-V PowerShell Direct Service", "Hyper-V Remote Desktop Virtualization Service", "Hyper-V Time Synchronization Service",
        "Hyper-V Volume Shadow Copy Requestor", "Intel(R) Content Protection HDCP Service", "Intel(R) Dynamic Application Loader Host Interface Service", "Intel(R) Management Engine WMI Provider Registration", "Intel(R) SUR QC Software Asset Manager",
        "Intel(R) System Usage Report Service SystemUsageReportSvc_QUEENCREEK", "Internet connection sharing", "IP Helper", "KtmRm for Distributed Transaction Coordinator", "Language Experience Service", "Link-Layer Topology Discovery Mapper",
        "Local Profile Assistant Service", "Local Session Manager", "Logi Options+", "McpManagementService", "Microsoft (R) Diagnostics Hub Standard Collector Service", "Microsoft App-V Client", "Microsoft Cloud Identity Service",
        "Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)", "Microsoft Edge Update Service (edgeupdate)", "Microsoft Edge Update Service (edgeupdatem)", "Microsoft Software Shadow Copy Provider", "Microsoft Store Install Service",
        "Microsoft Windows SMS Router Service.", "Net.Tcp Port Sharing Service", "Netlogon", "Network Connections", "Network Connected Devices Auto-Setup", "Network connection broker", "Offline files", "P9RdrService*",
        "Parental Control", "Payments and NFC/SE Manager", "PenService", "Performance Counter DLL Host", "Performance Logs & Alerts", "Plex Update Service", "PNRP Machine Name Publication Service", "Phone Service", "Portable Device Enumerator Service",
        "Print Spooler", "PrintWorkflow*", "Problem Reports Control Panel Support", "Program Compatibility Assistant Service", "Recommended Troubleshooting Service", "Remote Access Auto Connection Manager", "Remote Desktop Configuration",
        "Remote Desktop Services", "Remote Procedure Call (RPC) Locator", "Remote Registry", "Retail Demo Service", "Secondary logon", "Sensor Data Service", "Sensor Monitoring Service", "Server", "Shared PC Account Manager",
        "Smart Card", "Smart Card Device Enumeration Service", "Smart Card Removal Policy", "Software Protection", "Spatial Data Service", "SSDP Discovery", "Still Image Acquisition Events", "Storage Service", "Storage Tiers Management",
        "Sync Host*", "System Events Broker", "Task Scheduler", "Telephony", "TCP/IP NetBIOS Helper", "Text Input Management Service", "Themes", "Time Broker", "Touch Keyboard and Handwriting Panel Service", "Udk User Service*",
        "Update Orchestrator Service", "User Data Access*", "User Data Storage*", "User Energy Server Service queencreek", "User Experience Virtualization Service", "Volume Shadow Copy", "WaaSMedicSvc", "WalletService", "Warp JIT Service",
        "Web Threat Defense Service", "Web Threat Defense User Service*", "WebClient", "Windows Backup", "Windows Biometric Service", "Windows Camera Frame Server", "Windows Camera Frame Server Monitor", "Windows Error Reporting Service",
        "Windows Event Collector", "Windows Image Acquisition (WIA)", "Windows Insider Service", "Windows Installer", "Windows License Manager Service", "Windows Management Service", "Windows Mobile Hotspot Service", "Windows Modules Installer",
        "Windows Perception Service", "Windows Perception Simulation Service", "Windows Push Notifications System Service", "Windows Push Notifications User Service*", "Windows PushToInstall Service", "Windows Remote Management (WS-Management)",
        "Windows Search", "Windows Time", "Windows Update", "WMI Performance Adapter", "Xbox Accessory Management Service", "Xbox Live Auth Manager", "Xbox Live Game Save", "Xbox Live Networking Service"
    )
    $functionDefinition = (Get-Content function:\Manage-ServiceWithTimeout | Out-String)
    $originalServices = [System.Collections.ArrayList]::new()
    switch ($Mode) {
        'Disable-GameMode' {
            try {
                $importedServices = Import-Clixml -Path $ConfigFile -ErrorAction SilentlyContinue | Where-Object { $_.ServiceDisplayName -ne $null -and $_.Status -ne 'Stop-Service job timed out.' -and $_.Status -ne $null -and $_.ServiceName -ne $null -and $_.StartUpType -ne $null }
            }
            catch {
                Write-Error "Could not import the config file $ConfigFile error was: $($_.Exception.Message)"
            }
            $servicesStarted = 0
            $originalServices = $importedServices | ForEach-Object -ThrottleLimit 5 -Parallel {
                $functionScriptBlock = [scriptblock]::Create("function Manage-ServiceWithTimeout { $using:functionDefinition }")
                . $functionScriptBlock
                $result = $null
                $result = Manage-ServiceWithTimeout -DisplayName $PSItem.ServiceDisplayName -Mode Start-Service -Timeout 10 -StartupType $PSItem.StartUpType
                if ($($result.Status -ne 'Start-Service job timed out.')) {
                    $serviceInfo = [PSCustomObject]@{
                        Status             = $result.Status
                        ServiceDisplayName = $result.ServiceDisplayName
                        ServiceName        = $result.ServiceName
                        StartUpType        = $result.StartUpType
                    }
                    Return $serviceInfo
                }
            }
            foreach ($service in $originalServices) {
                if ($service.status -eq 'Running') {
                    $servicesStarted++
                    Write-verbose "Started service: $($service.ServiceDisplayName)"
                }
                else {
                    Write-verbose "Failed to start service: $($service.ServiceDisplayName)"
                }
            }
            Write-Host "Started $servicesStarted/$($importedServices.count) previously stopped services." -ForegroundColor Green
            Remove-Item -Path $ConfigFile -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        'Enable-GameMode' {
            $servicesStopped = 0
            $originalServices = $servicesToStop | ForEach-Object -ThrottleLimit 5 -Parallel {
                $functionScriptBlock = [scriptblock]::Create("function Manage-ServiceWithTimeout { $using:functionDefinition }")
                . $functionScriptBlock
                $result = $null
                $result = Manage-ServiceWithTimeout -DisplayName $PSItem -Mode Stop-Service -Timeout 10
                if ($($result.ServiceDisplayName)) {
                    $serviceInfo = [PSCustomObject]@{
                        Status             = $result.Status
                        ServiceDisplayName = $result.ServiceDisplayName
                        ServiceName        = $result.ServiceName
                        StartUpType        = $result.StartUpType
                    }
                    Return $serviceInfo
                }
            }
            foreach ($service in $originalServices) {
                if ($service.status -eq 'Stopped') {
                    $servicesStopped++
                    Write-verbose "Stopped service: $($service.ServiceDisplayName)"
                }
                else {
                    Write-verbose "Failed to stopped service: $($service.ServiceDisplayName)"
                }
            }
            Write-Host "Stopped $servicesStopped/$($servicesToStop.count) unnecessary services." -ForegroundColor Green
            try {
                $originalServices | Export-Clixml -Path $ConfigFile -Force -ErrorAction Stop
            }
            catch {
                Write-Error "Error exporting original service settings to config file: $($_.Exception.Message)"
            }
            try {
                $unnecessaryProcesses = Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.ProcessName -notin $excludedProcesses -and ($_.ProcessName -notin $whitelistedProcesses) }
            }
            catch {
                Write-Error "Could not generate the list of processes to stop. Error was: $($_.Exception.Message)"
            }
            $processesStopped = 0
            foreach ($process in $unnecessaryProcesses) {
                try {
                    Stop-Process -Name $process.ProcessName -Force -Confirm:$false -ErrorAction Stop
                    $processesStopped++
                    Write-verbose "Closing process: $($process.ProcessName)"
                }
                catch {
                    $processesStopped--
                    Write-verbose "Failed to close process: $($process.ProcessName)"
                }
            }
            if ($processesStopped -lt 0 ) {
                $processesStopped = 0
            }
            Write-Host "Stopped $processesStopped/$($unnecessaryProcesses.count) unnecessary processes." -ForegroundColor Green
        }
        default {
            Write-Host "Invalid mode specified. Please use 'Enable-GameMode' or 'Disable-GameMode'." -ForegroundColor Yellow
        }
    }
}
Toggle-GameMode -Mode Enable-GameMode -Verbose