Add-Type @'
    using System;
    using System.Text;
    using System.Runtime.InteropServices;
    public static class Win32API
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryInfoKey(
            IntPtr hkey, StringBuilder lpClass, ref int lpcbClass, IntPtr lpReserved,
            ref int lpcSubKeys, ref int lpcbMaxSubKeyLen, ref int lpcbMaxClassLen,
            ref int lpcValues, ref int lpcbMaxValueNameLen, ref int lpcbMaxValueLen,
            ref int lpcbSecurityDescriptor, out long lpftLastWriteTime);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FileTimeToSystemTime(ref long lpFileTime, out SYSTEMTIME lpSystemTime);
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            public short wYear;
            public short wMonth;
            public short wDayOfWeek;
            public short wDay;
            public short wHour;
            public short wMinute;
            public short wSecond;
            public short wMilliseconds;
        }
    }
'@
function Get-RegInfoByLastWriteTime {
    [CmdletBinding()] 
    param (
        [Parameter(Mandatory = $false)][string[]]$FullPaths
    )
    $currUser = ((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName.Trim()).Split('\')[1].Trim()
    $objUser = New-Object System.Security.Principal.NTAccount($currUser) -ErrorAction SilentlyContinue
    [string[]]$registryPaths = @("HKEY_USERS\$($objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value)\Software\Microsoft\Windows\CurrentVersion\Uninstall", 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $FullPaths = if ($null -eq $FullPaths) { $registryPaths } else { $FullPaths }
    $FixedPaths = $FullPaths | ForEach-Object { ($_ -replace '^HKLM(:|\\)', 'HKEY_LOCAL_MACHINE') -replace '^HKU(:|\\)', 'HKEY_USERS' -replace '^HKCU(:|\\)', 'HKEY_USERS' -replace '\+', '' }
    $HivePathData = $FixedPaths | ForEach-Object { ($_ -replace '([a-zA-Z_]+)\\(.*)', '$1,$2' -split ',') }
    $hive = @()
    $path = @()
    foreach ($item in $HivePathData) {
        if ($item.StartsWith("HKEY")) {
            $hive += $item
        }
        else {
            $path += $item
        }
    }
    $Subkeys = for ($i = 0; $i -lt $hive.Length; $i++) {
        if ($path[$i] -like 'S-1-5-*') {
            $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
            $subkeys = @($key.OpenSubKey("$($path[$i])").GetSubKeyNames())
            $key = 'Users-Default'
        }
        elseif ($path[$i] -like '*WOW6432Node*') {
            $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $subkeys = @($key.OpenSubKey("$($path[$i])").GetSubKeyNames())
            $key = 'LocalMachine-Registry64'
        }
        else {
            $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
            $subkeys = @($key.OpenSubKey("$($path[$i])").GetSubKeyNames())
            $key = 'LocalMachine-Registry32'
        }
        foreach ($Subkey in $Subkeys) {
            [pscustomobject]@{
                Subkey   = $Subkey
                Path     = "$($path[$i])"
                Key      = $key
                Hive     = if ($key -eq 'Users-Default') { 'HKEY_USERS' } else { 'HKEY_LOCAL_MACHINE' }
                FullPath = "$($path[$i])\$SubKey"
            }
        }
    }
    $results = New-Object System.Collections.ArrayList
    foreach ($subkeyName in $Subkeys) {
        try {
            switch ($subkeyName.Key) {
                'Users-Default' {
                    $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
                    $subkey = $key.OpenSubKey($($subkeyName.FullPath))
                }
                'LocalMachine-Registry64' { 
                    $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64) 
                    $subkey = $key.OpenSubKey($($subkeyName.FullPath))
                }
                'LocalMachine-Registry32' { 
                    $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32) 
                    $subkey = $key.OpenSubKey($($subkeyName.FullPath))
                }
            }
            $handle = $subkey.Handle.DangerousGetHandle()
            $lpftLastWriteTime, $lpcbClass, $lpcSubKeys, $lpcbMaxSubKeyLen, $lpcbMaxClassLen, $lpcValues, $lpcbMaxValueNameLen, $lpcbMaxValueLen, $lpcbSecurityDescriptor = 0, 0, 0, 0, 0, 0, 0, 0, 0 
            [Win32API]::RegQueryInfoKey($handle, [System.Text.StringBuilder]::new(), [ref]$lpcbClass, [System.IntPtr]::Zero, [ref]$lpcSubKeys, [ref]$lpcbMaxSubKeyLen, [ref]$lpcbMaxClassLen, [ref]$lpcValues, [ref]$lpcbMaxValueNameLen, [ref]$lpcbMaxValueLen, [ref]$lpcbSecurityDescriptor, [ref]$lpftLastWriteTime) | Out-null
            $lastWriteTime = [DateTime]::FromFileTime($lpftLastWriteTime).ToString('yyyy-MM-dd HH:mm:ss.ffff')
            $displayName = $subkey.GetValue('DisplayName')
            $QuietUninstallString = $subkey.GetValue('QuietUninstallString')
            $UninstallString = $subkey.GetValue('UninstallString')
            if ($lastWriteTime -and $displayName) {
                $displayNames = $results | ForEach-Object { $_.DisplayName }-ErrorAction SilentlyContinue
                if ($displayNames -contains $displayName) {
                    continue
                }
                else {
                    $results.Add([pscustomobject]@{
                            DisplayName          = $displayName
                            DisplayVersion       = $subkey.GetValue('DisplayVersion')
                            LastWriteTime        = $lastWriteTime
                            UninstallString      = ($UninstallString -replace '^""', '')
                            QuietUninstallString = ($QuietUninstallString -replace '^""', '')
                            InstallSource        = $subkey.GetValue('InstallSource')
                            InstallLocation      = $subkey.GetValue('InstallLocation')
                            InstallDate          = $subkey.GetValue('InstallDate')
                            ModifyPath           = $subkey.GetValue('ModifyPath')
                            LogFile              = $subkey.GetValue('LogFile')
                            WindowsInstaller     = $subkey.GetValue('WindowsInstaller')
                            Language             = $subkey.GetValue('Language')
                            Publisher            = $subkey.GetValue('Publisher')
                            HIVE                 = $subkeyName.Hive
                            Path                 = $subkeyName.Path
                            Key                  = $subkeyName.Subkey
                            FullPath             = "$($subkeyName.Hive)\$($subkeyName.FullPath)"
                        }) | Out-Null
                }
            }
        }
        catch { $_ | Select-Object * | Write-Host }
    }
    return $results | Sort-Object -Property LastWriteTime -Descending
}