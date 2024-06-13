function Manage-ServiceWithTimeout {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$DisplayName,
        [int]$Timeout = 5,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stop-Service', 'Start-Service')]
        [string]$Mode
    )
    Process {
        switch ($Mode) {
            'Stop-Service' {
                $job = Start-Job -ScriptBlock {
                    param($DisplayName)
                    Stop-Service -DisplayName $DisplayName -Force -Confirm:$false -ErrorAction SilentlyContinue -PassThru
                } -ArgumentList $DisplayName
            }
            'Start-Service' {
                $job = Start-Job -ScriptBlock {
                    param($DisplayName)
                    Start-Service -DisplayName $DisplayName -Force -Confirm:$false -ErrorAction SilentlyContinue -PassThru
                } -ArgumentList $DisplayName
            }
        }
        Write-Host 'Job: ' ($job)
        $waitResult = $job | Wait-Job -Timeout $timeout -ErrorAction SilentlyContinue
        if ($waitResult) {
            $result = $job | Receive-Job -ErrorAction SilentlyContinue 
            Write-Host 'Result ' ($Result)
            Remove-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
            if ($Mode -eq 'Stop-Server') {
                return @{
                    'Stopped' = $true
                    'Service' = $result
                }
            }
            else {
                return @{
                    'Started' = $true
                    'Service' = $result
                }
            }
        }
        else {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
            if ($mode -eq 'Stop-Service') {
                return @{
                    'Stopped' = $false
                    'Service' = $null
                }
            }
            else {
                return @{
                    'Started' = $false
                    'Service' = $null
                }
            }
        }
    }
}
function Toggle-GameMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable-GameMode', 'Disable-GameMode')]
        [string]$Mode,
        [string]$ConfigFile = "./ServicesConfig.xml",
        $ExcludeProcesses = @('plex media server', 'ROCCAT_Swarm_Monitor', 'pcee4', 'pcee4e', 'XtuService')
    )
    if (-not (Test-Path $ConfigFile -PathType Leaf)) {
        @() | Export-Clixml -Path $ConfigFile
    }
    $whitelist = @(
        'System', 'svchost', 'wininit', 'winlogon', 'services', 'csrss', 'conhost', 'dwm', 'explorer', 'smss', 'lsass', 'MsMpEng', 'ctfmon', 'WmiPrvSE', 'taskhostw', 'sihost', 'RuntimeBroker',
        'Registry', 'Idle', 'dasHost', 'StartMenuExperienceHost', 'TextInputHost', 'SearchHost', 'dllhost', 'fontdrvhost', 'lsaiso', 'SecHealthUI', 'SecurityHealthService', 'SgrmBroker', 'crashpad_handler',
        'ApplicationFrameHost', 'LsaIso', 'SecurityHealthHost', 'code', 'pwsh', 'powershell', 'LockApp', 'SystemSettingsBroker', 'ShellExperienceHost', 'Secure System', 'Opera', 'audiodg', 'WMIADAP', 'qbittorrent'
    )
    $whitelistServices = @(
        'Background Tasks Infrastructure Service'  
    )
    #"Application Information",
    $servicesToDisable = @(   
        "Background Tasks Infrastructure Service",
        "Clipboard User Service_4b14f"
    )
    switch ($Mode) {
        'Disable-GameMode' {
            try {
                $stoppedServices = Import-Clixml -Path $ConfigFile -ErrorAction SilentlyContinue
            }
            catch {
                Write-Error "Could not import the config file $ConfigFile error was: $($_.Exception.Message)"
            }
            foreach ($svc in $stoppedServices) {
                $service = Get-Service -Name $svc.Name
                if ($service.Status -ne "Running") {
                    Start-Service -Name $svc.Name -Confirm:$false -ErrorAction SilentlyContinue
                }
                Set-Service -Name $svc.Name -StartupType $svc.StartupType -Force -Confirm:$false -ErrorAction SilentlyContinue
            }
            Remove-Item -Path $ConfigFile -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        'Enable-GameMode' {
            $processNameExclusions = $whitelist + $ExcludeProcesses
            try {
                $unnecessaryProcesses = Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.ProcessName -notin $processNameExclusions }
            }
            catch {
                Write-Error "Could not generate the list of processes to stop. Error was: $($_.Exception.Message)"
            }
            $processesStopped = 0
            foreach ($process in $unnecessaryProcesses) {
                try {
                    Stop-Process -Id $process.Id -Force -Confirm:$false -ErrorAction Stop
                    $processesStopped++
                }
                catch {
                    $processesStopped--
                }
            }
            Write-Host "Stopped $processesStopped unnecessary processes." -ForegroundColor Green
            $servicesStopped = 0
            $originalServices = [System.Collections.ArrayList]::new()
            $functionDefinition = (Get-Content function:\Manage-ServiceWithTimeout | Out-String)
            $servicesToDisable | ForEach-Object -ThrottleLimit 10 -Parallel {
                $functionScriptBlock = [scriptblock]::Create("function Manage-ServiceWithTimeout { $using:functionDefinition }")
                . $functionScriptBlock
                Write-Host 'PSItem ' ($PSItem)
                $svcName = $PSItem
                $stopResult = Manage-ServiceWithTimeout -DisplayName $svcName -Mode Stop-Service -Timeout 5
                Write-Host 'Stopp resultat' ($Stopresult)
                $svc = Get-Service -DisplayName $svcName -ErrorAction SilentlyContinue | Select-Object Name, StartupType, DisplayName
                if ($stopResult.Stopped) {
                    Write-Host 'svc if' ($svc)
                    @{
                        Name        = $svc.Name
                        StartupType = $svc.StartupType
                        Stopped     = $true
                    }
                }
                else {
                    Write-Host 'svc else' ($svc)
                    @{
                        Name        = $svc.Name
                        StartupType = $svc.StartupType
                        Stopped     = $false
                    }
                }
            } | ForEach-Object {
                if ($_.Name -and -not ($_.Name -is [Object[]])) {
                    $originalServices.Add($_) | Out-Null
                    Set-Service -Name $_.Name -StartupType Manual -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            foreach ($item in $originalServices) {
                if ($item.Stopped) {
                    $servicesStopped++
                }
                else {
                    $servicesStopped--
                }
            }
            Write-Host "Stopped $servicesStopped unnecessary services." -ForegroundColor Green
            try {
                $originalServices | Export-Clixml -Path $ConfigFile -Force -ErrorAction Stop
            }
            catch {
                Write-Error "Error exporting original service settings to config file: $($_.Exception.Message)"
            }
        }
        default {
            Write-Host "Invalid mode specified. Please use 'Enable-GameMode' or 'Disable-GameMode'." -ForegroundColor Yellow
        }
    }
}
Toggle-GameMode Enable-GameMode
#Install-Module PSTask -Verbose -Force
#"Application Information"
#  "Background Tasks Infrastructure Service",
#    "CoreMessaging",
$servicesToDisable = @(
    "AVCTP Service",
    "AllJoyn Router Service",
    "Background Intelligent Transfer Service",
    "BitLocker Drive Encryption Service",
    "Block Level Backup Engine Service",
    "Bluetooth Audio Gateway Service",
    "Bluetooth Support Service",
    "Bluetooth User Support Service*",
    "BranchCache",
    "COM+ Event System",
    "COM+ System Application",
    "CaptureService*",
    "Cellular Time",
    "Certificate propagation",
    "Client License Service (ClipSVC)",
    "Connected Devices Platform Service",
    "Connected Devices Platform User Service*",
    "Connected User Experiences and Telemetry",
    "Contact Data*",
    "Credential Manager",
    "CredentialEnrollmentManagerUserSvc*",
    "Data Sharing Service",
    "Data Usage",
    "Device Association Service",
    "Device Association Broker*",
    "Device Management Enrollment Service",
    "Device Management Wireless Application Protocol (WAP) Push message Routing Service",
    "DevQuery Background Discovery Broker",
    "Diagnostic Execution Service",
    "Diagnostic Policy Service",
    "Diagnostic Service Host",
    "Diagnostic System Host",
    "Distributed Link Tracking Client",
    "Distributed Transaction Coordinator",
    "Downloaded Maps Manager",
    "Embedded Mode",
    "Enterprise App Management Service",
    "Energy Server Service queencreek",
    "FAX",
    "File History Service",
    "Function Discovery Provider Host",
    "Function Discovery Resource Publication",
    "GameDVR and Broadcast User Service*",
    "Geolocation Service",
    "Google Update Service (gupdatem)",
    "Google Update Service (gupdate)",
    "HV Host Service",
    "Hyper-V Guest Service Interface",
    "Hyper-V Guest Shutdown Service",
    "Hyper-V Heartbeat Service",
    "Hyper-V PowerShell Direct Service",
    "Hyper-V Remote Desktop Virtualization Service",
    "Hyper-V Time Synchronization Service",
    "Hyper-V Volume Shadow Copy Requestor",
    "Intel(R) Content Protection HDCP Service",
    "Intel(R) Dynamic Application Loader Host Interface Service",
    "Intel(R) Management Engine WMI Provider Registration",
    "Intel(R) SUR QC Software Asset Manager",
    "Intel(R) System Usage Report Service SystemUsageReportSvc_QUEENCREEK",
    "Internet connection sharing",
    "IP Helper",
    "KtmRm for Distributed Transaction Coordinator",
    "Language Experience Service",
    "Link-Layer Topology Discovery Mapper",
    "Local Profile Assistant Service",
    "Local Session Manager",
    "Logi Options+",
    "McpManagementService",
    "Microsoft (R) Diagnostics Hub Standard Collector Service",
    "Microsoft App-V Client",
    "Microsoft Cloud Identity Service",
    "Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)",
    "Microsoft Edge Update Service (edgeupdate)",
    "Microsoft Edge Update Service (edgeupdatem)",
    "Microsoft Software Shadow Copy Provider",
    "Microsoft Store Install Service",
    "Microsoft Windows SMS Router Service.",
    "Net.Tcp Port Sharing Service",
    "Netlogon",
    "Network Connections",
    "Network Connected Devices Auto-Setup",
    "Network connection broker",
    "NPSMSvc*",
    "Offline files",
    "P9RdrService*",
    "Parental Control",
    "Payments and NFC/SE Manager",
    "PenService",
    "Performance Counter DLL Host",
    "Performance Logs & Alerts",
    "Plex Update Service",
    "PNRP Machine Name Publication Service",
    "Phone Service",
    "Portable Device Enumerator Service",
    "Print Spooler",
    "PrintWorkflow*",
    "Problem Reports Control Panel Support",
    "Program Compatibility Assistant Service",
    "Recommended Troubleshooting Service",
    "Remote Access Auto Connection Manager",
    "Remote Desktop Configuration",
    "Remote Desktop Services",
    "Remote Procedure Call (RPC) Locator",
    "Remote Registry",
    "Retail Demo Service",
    "Secondary logon",
    "Sensor Data Service",
    "Sensor Monitoring Service",
    "Server",
    "Shared PC Account Manager",
    "Smart Card",
    "Smart Card Device Enumeration Service",
    "Smart Card Removal Policy",
    "Software Protection",
    "Spatial Data Service",
    "SSDP Discovery",
    "Still Image Acquisition Events",
    "Storage Service",
    "Storage Tiers Management",
    "Sync Host*",
    "System Events Broker",
    "Task Scheduler",
    "TeamViewer",
    "Telephony",
    "TCP/IP NetBIOS Helper",
    "Text Input Management Service",
    "Themes",
    "Time Broker",
    "Touch Keyboard and Handwriting Panel Service",
    "Udk User Service*",
    "Update Orchestrator Service",
    "User Data Access*",
    "User Data Storage*",
    "User Energy Server Service queencreek",
    "User Experience Virtualization Service",
    "Volume Shadow Copy",
    "WaaSMedicSvc",
    "WalletService",
    "Warp JIT Service",
    "Web Threat Defense Service",
    "Web Threat Defense User Service*",
    "WebClient",
    "Windows Backup",
    "Windows Biometric Service",
    "Windows Camera Frame Server",
    "Windows Camera Frame Server Monitor",
    "Windows Error Reporting Service",
    "Windows Event Collector",
    "Windows Image Acquisition (WIA)",
    "Windows Insider Service",
    "Windows Installer",
    "Windows License Manager Service",
    "Windows Management Service",
    "Windows Mobile Hotspot Service",
    "Windows Modules Installer",
    "Windows Perception Service",
    "Windows Perception Simulation Service",
    "Windows Push Notifications System Service",
    "Windows Push Notifications User Service*",
    "Windows PushToInstall Service",
    "Windows Remote Management (WS-Management)",
    "Windows Search",
    "Windows Time",
    "Windows Update",
    "WMI Performance Adapter",
    "WinHTTP Web Proxy Auto-Discovery Service",
    "Xbox Accessory Management Service",
    "Xbox Live Auth Manager",
    "Xbox Live Game Save",
    "Xbox Live Networking Service"
)
