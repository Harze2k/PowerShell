function ManageServiceWithTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]	
        [string]$DisplayName,
        [int]$Timeout = 5,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stop-Service', 'Start-Service')]
        [string]$Mode,
        [string]$StartUpType = 'Manual'
    )
    if ((Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue | Select-Object Status -ErrorAction SilentlyContinue).Status -ne 'Running' -and ($Mode -eq 'Start-Service')) {
        Write-Host "Starting: $displayname"
        $job = Start-Job -ScriptBlock {
            param([string]$DisplayName, [string]$StartUpType, [string]$Mode)
            & $Mode -DisplayName $DisplayName -Confirm:$false -ErrorAction SilentlyContinue -PassThru | Set-Service -StartupType $StartUpType -PassThru -ErrorAction SilentlyContinue
        } -ArgumentList $DisplayName, $StartUpType, $Mode
    }
    elseif ((Get-Service -DisplayName $DisplayName -ErrorAction SilentlyContinue | Select-Object Status -ErrorAction SilentlyContinue).Status -eq 'Running' -and ($Mode -eq 'Stop-Service')) {
        $job = Start-Job -ScriptBlock {
            param([string]$DisplayName, [string]$StartUpType, [string]$Mode)
            & $Mode -DisplayName $DisplayName -Confirm:$false -ErrorAction SilentlyContinue -PassThru | Set-Service -StartupType $StartUpType -PassThru -ErrorAction SilentlyContinue
        } -ArgumentList $DisplayName, $StartUpType, $Mode
    }
    else {
        $output = @{
            'Status'             = if ($Mode -eq 'Start-Service') { 'Service already started'; Write-Host "Not Starting $displayname" } else { 'Service already stopped' }
            'ServiceDisplayName' = $DisplayName
            'StartUpType'        = $StartUpType
        }
        return $output
    }
    $job | Wait-Job -Timeout $timeout -ErrorAction SilentlyContinue | Out-Null
    $result = $job | Receive-Job -Force -Wait -ErrorAction SilentlyContinue
    Remove-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
    $output = @{
        'Status'             = if ($result.Status) { $result.Status } else { "$mode job timed out." }
        'ServiceDisplayName' = $DisplayName
        'StartUpType'        = $StartUpType
    }
    return $output 
}
function SavedRAM {
    [CmdletBinding()]
    param(
        [int]$AvailableMemory = 0,
        [int]$UsedMemory = 0,
        [switch]$After
    )
    Add-Type -AssemblyName "Microsoft.VisualBasic"
    $computerInfo = New-Object Microsoft.VisualBasic.Devices.ComputerInfo
    $totalMemory = [int][math]::Round($computerInfo.TotalPhysicalMemory / 1MB, 2)
    if ($after) {
        $afterAvailableMemory = [int][math]::Round(($computerInfo.TotalPhysicalMemory - $computerInfo.AvailablePhysicalMemory) / 1MB, 2)
        $afterUsedMemory = $totalMemory - $afterAvailableMemory
        $ram = @{
            'Total RAM'            = $totalMemory
            'Used RAM Before'      = $usedMemory
            'Used RAM After'       = $afterUsedMemory
            'Available RAM Before' = $availableMemory
            'Available RAM After'  = $afterAvailableMemory
            'Saved'                = ($AvailableMemory - $afterAvailableMemory)
        }
        Return $ram
    }
    else {
        $availableMemory = [int][math]::Round(($computerInfo.TotalPhysicalMemory - $computerInfo.AvailablePhysicalMemory) / 1MB, 2)
        $usedMemory = $totalMemory - $availableMemory
        $ram = @{
            'Total RAM'            = $totalMemory
            'Used RAM Before'      = $usedMemory
            'Available RAM Before' = $availableMemory
        }
        Return $ram
    }
}
function ToggleGameMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        #[ValidateSet('Enable-GameMode', 'Disable-GameMode')]
        [string]$Mode = '',
        [string]$ConfigFile = './ServicesConfig.xml',
        $ExcludedProcesses = @('plex media server', 'ROCCAT_Swarm_Monitor', 'pcee4', 'XtuService', 'qbittorrent', 'pwsh', 'powershell', 'powershell_ise', 'SVPManager', 'PowerShell Studio', 'SAPIEN Script Packager', 'opera', 'code', 'GoogleDriveFS', 'ProcessLasso', 'ProcessGovernor'),
        [switch]$Turbo,
        [int]$NumberOfParallelJobs = ([System.Environment]::ProcessorCount) - 2
    )
    if ($turbo) {
        $excludedProcesses = @('pwsh', 'pcee4', 'ROCCAT_Swarm_Monitor', 'code')
    }
    if ((Test-Path $ConfigFile) -and ($Mode -eq '')) {
        $Mode = 'Disable-GameMode'
    }
    if (!(Test-Path $ConfigFile) -and ($Mode -eq '')) {
        $Mode = 'Enable-GameMode'
    }
    $whitelistedProcesses = @(
        'System', 'svchost', 'wininit', 'winlogon', 'services', 'csrss', 'conhost', 'dwm', 'explorer', 'smss', 'lsass', 'MsMpEng', 'ctfmon', 'WmiPrvSE', 'taskhostw', 'sihost', 'RuntimeBroker',
        'Registry', 'Idle', 'dasHost', 'StartMenuExperienceHost', 'TextInputHost', 'SearchHost', 'dllhost', 'fontdrvhost', 'lsaiso', 'SecurityHealthService', 'SgrmBroker',
        'ApplicationFrameHost', 'LsaIso', 'SecurityHealthHost', 'LockApp', 'SystemSettingsBroker', 'ShellExperienceHost', 'Secure System', 'audiodg', 'WMIADAP', 'Memory Compression', 'HotPatch', 'NisSrv', 'NVDisplay.Container'
    )
    $whitelistedServices = @( 
        'Print Spooler', 'Logi Options+', 'AppIDSvc'
    )
    $servicesToStop = @(
        'AppX Deployment Service (AppXSVC)', 'AVCTP Service', 'AllJoyn Router Service', 'Background Intelligent Transfer Service', 'BitLocker Drive Encryption Service', 'BranchCache', 'COM+ Event System', 'COM+ System Application', 'CaptureService*', 'Cellular Time', 'Certificate propagation', 'Client License Service (ClipSVC)', 'Connected Devices Platform Service',
        'Connected Devices Platform User Service*', 'Connected User Experiences and Telemetry', 'Contact Data*', 'CredentialEnrollmentManagerUserSvc*', 'Data Sharing Service', 'Data Usage', 'Device Association Service', 'Device Association Broker*',
        'Device Management Enrollment Service', 'Device Management Wireless Application Protocol (WAP) Push message Routing Service', 'DevQuery Background Discovery Broker', 'Diagnostic Execution Service', 'Diagnostic Policy Service',
        'Diagnostic Service Host', 'Diagnostic System Host', 'Distributed Link Tracking Client', 'Distributed Transaction Coordinator', 'Downloaded Maps Manager', 'Embedded Mode', 'Enterprise App Management Service', 'Energy Server Service queencreek',
        'FAX', 'File History Service', 'Function Discovery Provider Host', 'Function Discovery Resource Publication', 'GameDVR and Broadcast User Service*', 'Geolocation Service', 'Google Update Service (gupdatem)', 'Google Update Service (gupdate)',
        'HV Host Service', 'Hyper-V Guest Service Interface', 'Hyper-V Guest Shutdown Service', 'Hyper-V Heartbeat Service', 'Hyper-V PowerShell Direct Service', 'Hyper-V Remote Desktop Virtualization Service', 'Hyper-V Time Synchronization Service',
        'Hyper-V Volume Shadow Copy Requestor', 'Intel(R) Content Protection HDCP Service', 'Intel(R) Dynamic Application Loader Host Interface Service', 'Intel(R) Management Engine WMI Provider Registration', 'Intel(R) SUR QC Software Asset Manager',
        'Intel(R) System Usage Report Service SystemUsageReportSvc_QUEENCREEK', 'Internet connection sharing', 'IP Helper', 'KtmRm for Distributed Transaction Coordinator', 'Language Experience Service', 'Link-Layer Topology Discovery Mapper',
        'Local Profile Assistant Service', 'Local Session Manager', 'McpManagementService', 'Microsoft (R) Diagnostics Hub Standard Collector Service', 'Microsoft App-V Client', 'Microsoft Cloud Identity Service',
        'Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)', 'Microsoft Passport Container', 'Microsoft Edge Update Service (edgeupdate)', 'Microsoft Edge Update Service (edgeupdatem)', 'Microsoft Software Shadow Copy Provider', 'Microsoft Store Install Service',
        'Microsoft Windows SMS Router Service.', 'Net.Tcp Port Sharing Service', 'Netlogon', 'Network Connections', 'Network List Service', 'Network Connected Devices Auto-Setup', 'Network connection broker', 'Offline files', 'P9RdrService*',
        'Parental Control', 'Payments and NFC/SE Manager', 'PenService', 'Performance Counter DLL Host', 'Performance Logs & Alerts', 'Plex Update Service', 'PNRP Machine Name Publication Service', 'Phone Service', 'Portable Device Enumerator Service',
        'PrintWorkflow*', 'Problem Reports Control Panel Support', 'Program Compatibility Assistant Service', 'Recommended Troubleshooting Service', 'Remote Access Auto Connection Manager', 'Remote Desktop Configuration',
        'Remote Desktop Services', 'Remote Procedure Call (RPC) Locator', 'Remote Registry', 'Retail Demo Service', 'Secondary logon', 'Sensor Data Service', 'Sensor Monitoring Service', 'Server', 'Shared PC Account Manager',
        'Smart Card', 'Smart Card Device Enumeration Service', 'Smart Card Removal Policy', 'Software Protection', 'Spatial Data Service', 'SSDP Discovery', 'Still Image Acquisition Events', 'Storage Service', 'Storage Tiers Management',
        'Sync Host*', 'System Events Broker', 'System Event Notification Service', 'Task Scheduler', 'Telephony', 'TCP/IP NetBIOS Helper', 'Text Input Management Service', 'Themes', 'Time Broker', 'Touch Keyboard and Handwriting Panel Service', 'Udk User Service*',
        'Update Orchestrator Service', 'User Data Access*', 'User Data Storage*', 'User Energy Server Service queencreek', 'User Experience Virtualization Service', 'Volume Shadow Copy', 'WaaSMedicSvc', 'WalletService', 'Warp JIT Service', 'Web Account Manager',
        'Web Threat Defense Service', 'Web Threat Defense User Service*', 'WebClient', 'Windows Backup', 'Windows Biometric Service', 'Windows Camera Frame Server', 'Windows Camera Frame Server Monitor', 'Windows Error Reporting Service',
        'Windows Event Collector', 'Windows Image Acquisition (WIA)', 'Windows Insider Service', 'Windows Installer', 'Windows License Manager Service', 'Windows Management Service', 'Windows Mobile Hotspot Service', 'Windows Modules Installer',
        'Windows Perception Service', 'Windows Perception Simulation Service', 'Windows Push Notifications System Service', 'Windows Push Notifications User Service*', 'Windows PushToInstall Service', 'Windows Remote Management (WS-Management)',
        'Windows Search', 'Windows Time', 'Windows Update', 'WMI Performance Adapter', 'Xbox Accessory Management Service', 'Xbox Live Auth Manager', 'Xbox Live Game Save', 'Xbox Live Networking Service'
    )
    $funcDef = $function:ManageServiceWithTimeout.ToString()
    switch ($Mode) {
        'Disable-GameMode' {
            Write-Host 'Disabling GameMode..'
            if (-not (Test-Path $ConfigFile -PathType Leaf)) {
                throw "No config file was found in $((Get-Location).Path). Need to run Toggle-GameMode -Mode Enable-GameMode to generate a workable file to restore services to a running state."
            }
            try {
                $importedServices = Import-Clixml -Path $ConfigFile -ErrorAction SilentlyContinue | Where-Object { $_.ServiceDisplayName -ne $null -and $_.Status -ne 'Stop-Service job timed out.' -and $_.Status -ne $null -and $_.StartUpType -ne $null }
            }
            catch {
                Write-Error "Could not import the config file $ConfigFile error was: $($_.Exception.Message)"
            }
            $executionTimeServices = Measure-Command -Expression {
                #$originalServices = $importedServices | ForEach-Object {
                $originalServices = $importedServices | ForEach-Object -ThrottleLimit $NumberOfParallelJobs -Parallel {
                    $function:ManageServiceWithTimeout = $using:funcDef
                    $result = ManageServiceWithTimeout -DisplayName $PSItem.ServiceDisplayName -Mode Start-Service -Timeout 5 -StartupType $PSItem.StartUpType
                    if ($result.Status -ne 'Start-Service job timed out.') {
                        return $result
                    }
                }
            }
            $originalServices | Where-Object { $_.Status -eq 'Running' } -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Started service: $($_.ServiceDisplayName)" } -ErrorAction SilentlyContinue
            $originalServices | Where-Object { $_.Status -ne 'Running' } -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Failed to start service: $($_.ServiceDisplayName)" -ForegroundColor Yellow } -ErrorAction SilentlyContinue
            $servicesStarted = ($originalServices | Where-Object { $_.Status -eq 'Running' }).Count
            $servicesNotStarted = ($originalServices | Where-Object { $_.Status -ne 'Running' }).Count
            Write-Host "Started $servicesStarted/$($importedServices.count) previously stopped services." -ForegroundColor Green
            Write-Host "Starting all the $servicesStarted services tock $($executionTimeServices.TotalSeconds) seconds." -ForegroundColor Green
            Write-Host "Failed to start $($servicesNotStarted.count) previously stopped services." -ForegroundColor Yellow
            Remove-Item -Path $ConfigFile -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        'Enable-GameMode' {
            Write-Host 'Enabling GameMode..'
            Write-Host 'Usually takes about 1 minute..'
            if (-not (Test-Path $ConfigFile -PathType Leaf)) {
                @() | Export-Clixml -Path $ConfigFile
            }
            $before = SavedRAM
            $totalProcessesBefore = Get-Process -IncludeUserName | Select-Object ProcessName
            $unnecessaryServices = $servicesToStop | Where-Object { $_ -notin $whitelistedServices }
            $runningServicesBefore = ((Get-Service -ErrorAction SilentlyContinue | Select-Object DisplayName, Status | Where-Object { $_.Status -eq 'Running' }).Count)
            $executionTimeServices = Measure-Command -Expression {
                $originalServices = $unnecessaryServices | ForEach-Object -ThrottleLimit $NumberOfParallelJobs -Parallel {
                    $function:ManageServiceWithTimeout = $using:funcDef
                    $result = ManageServiceWithTimeout -DisplayName $PSItem -Mode Stop-Service -Timeout 5
                    if ($result.Status -ne 'Stop-Service job timed out.') {
                        return $result
                    }
                }
            }
            $servicesStopped = ($originalServices | Where-Object { $_.Status -eq 'Stopped' }).Count
            $originalServices | Export-Clixml -Path $ConfigFile -Force -ErrorAction Stop
            $unnecessaryProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -notin $excludedProcesses -and ($_.ProcessName -notin $whitelistedProcesses) }
            $resultatProcesses = $unnecessaryProcesses | ForEach-Object {
                try {
                    Stop-Process -Name $_.ProcessName -Force -Confirm:$false -ErrorAction Stop
                    $output = @{
                        'Stopped'     = $true
                        'ProcessName' = $($_.ProcessName)
                        'Error'       = ''
                    }
                    Return $output
                }
                catch {
                    $output = @{
                        'Stopped'     = $false
                        'ProcessName' = $($_.ProcessName)
                        'Error'       = $($_.Exception.Message)
                    }
                    Return $output
                }
            } 
            $resultatProcesses | Select-Object Stopped, ProcessName -Unique | Where-Object { $_.Stopped -eq $true } | ForEach-Object { Write-Host "Stopped process: $($_.ProcessName)" }
            $resultatProcesses | Select-Object Stopped, ProcessName -Unique | Where-Object { $_.Stopped -ne $true -and $_.ProcessName -ne '' } | ForEach-Object { Write-Host "Failed to stop process: $($_.ProcessName)" -ForegroundColor Yellow }
            $originalServices | select-object Status, ServiceDisplayName | Where-Object { $_.Status -eq 'Stopped' } -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Stopped service: $($_.ServiceDisplayName)" }
            $originalServices | select-object Status, ServiceDisplayName | Where-Object { $_.Status -ne 'Stopped' } -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Failed to stopped service: $($_.ServiceDisplayName)" -ForegroundColor Yellow }
            Write-Host "There was $($totalProcessesBefore.count) running processes before, now its $((Get-Process -ErrorAction SilentlyContinue).Count)." -ForegroundColor Green
            Write-Host "Stopped $(($resultatProcesses | Select-Object Stopped, ProcessName | Where-Object { $_.Stopped -eq $true }).Count)/$($unnecessaryProcesses.count) unnecessary processes." -ForegroundColor Green
            $runningServicesAfter = ((Get-Service -ErrorAction SilentlyContinue | Select-Object Status | Where-Object { $_.Status -eq 'Running' }).Count)
            Write-Host "There was $runningServicesBefore running services before, now its $runningServicesAfter." -Verbose -ForegroundColor Green
            Write-Host "Stopping all the $($runningServicesBefore-$runningServicesAfter) services tock $($executionTimeServices.TotalSeconds) seconds" -ForegroundColor Green
            $after = SavedRAM -After -AvailableMemory $before.'Available RAM Before' -UsedMemory $before.'Used RAM Before'
            Write-Host "Saved $($after.Saved) MB Ram" -ForegroundColor Green
        }
        default {
            Write-Host "Invalid mode specified. Please use 'Enable-GameMode' or 'Disable-GameMode'." -ForegroundColor Yellow
        }
    }
}
<#
How to make an EXE for the script:
Install-Module -Name PS2EXE -Force -Verbose -Scope CurrentUser -Confirm:$false
Import-Module -Name PS2EXE -Force -Verbose -Scope Global
Example: 
Invoke-PS2EXE -inputFile .\Start-Toggle-GameMode.ps1 -outputFile .\Start-Toggle-GameMode.exe -x64 -MTA -title 'GameMode' -version '1.2' -requireAdmin -noConfigFile
#>
ToggleGameMode -Mode Enable-GameMode -Turbol