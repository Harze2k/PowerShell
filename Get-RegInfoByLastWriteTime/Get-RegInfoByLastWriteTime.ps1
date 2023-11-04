<#
Description: This C# code snippet provides a set of utility functions for querying Windows registry key information and converting file time to system time. The code leverages Platform Invoke (P/Invoke) to call native Win32 API functions from the advapi32.dll and kernel32.dll libraries.
Win32API Class
The Win32API class contains the following members:
RegQueryInfoKey Function
This static function is a wrapper around the native RegQueryInfoKey function from the advapi32.dll library. It retrieves information about a specified registry key, such as the number of subkeys, values, and the last write time. The function accepts the following parameters:
    hkey: A handle to the registry key.
    lpClass: A pointer to a buffer that receives the key class.
    lpcbClass: A pointer to a variable that specifies the size of the buffer pointed to by the lpClass parameter, in characters.
    lpReserved: Reserved; must be IntPtr.Zero.
    lpcSubKeys: A pointer to a variable that receives the number of subkeys that the key contains.
    lpcbMaxSubKeyLen: A pointer to a variable that receives the size of the key's longest subkey name, in characters.
    lpcbMaxClassLen: A pointer to a variable that receives the size of the longest string that specifies a subkey's class, in characters.
    lpcValues: A pointer to a variable that receives the number of values that are associated with the key.
    lpcbMaxValueNameLen: A pointer to a variable that receives the size of the key's longest value name, in characters.
    lpcbMaxValueLen: A pointer to a variable that receives the size of the key's longest value data, in bytes.
    lpcbSecurityDescriptor: A pointer to a variable that receives the size of the key's security descriptor, in bytes.
    lpftLastWriteTime: A pointer to a variable that receives the last write time.
FileTimeToSystemTime Function
This static function is a wrapper around the native FileTimeToSystemTime function from the kernel32.dll library. It converts a file time to system time format. The function accepts the following parameters:
lpFileTime: A pointer to a long variable containing the file time to be converted.
lpSystemTime: A pointer to a SYSTEMTIME structure that receives the converted system time.
SYSTEMTIME Structure
#>
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
<##
This PowerShell function, Get-RegInfoByLastWriteTime, retrieves information about installed software on a Windows system by querying the registry keys associated with installed software. The function primarily focuses on obtaining the software's last write time, but it also collects other relevant information, such as display name, display version, uninstall strings, install location, and more.
Function Parameters:
[Optional] $FullPaths: A string array containing custom registry paths to be queried. If not provided, default registry paths for uninstall information will be used.
Function Process:
    1. Retrieves the current user's username and creates a new NTAccount object for the user.
    2. Defines default registry paths for the software uninstall keys in the user and system hives.
    3. Replaces any registry path abbreviations with their full paths and separates the hive and path for each registry key.
    4. Iterates through the registry keys, opening the corresponding subkeys and extracting their subkey names.
    5. For each subkey, creates a custom PowerShell object containing the subkey name, path, key, and hive information.
    6. Iterates through the subkeys and opens the corresponding registry key based on the key property (Users-Default, LocalMachine-Registry64, or LocalMachine-Registry32).
    7. Queries the registry key for information using the Win32API RegQueryInfoKey method, and retrieves the last write time of the key.
    8. Retrieves additional information from the subkey, such as display name, uninstall strings, and more.
    9. If the last write time and display name are valid and unique, adds a custom PowerShell object containing the retrieved information to the results list.
    10. Returns the results list, sorted by the last write time in descending order.
The output of this function is a sorted list of PowerShell custom objects containing information about installed software on the system, primarily focusing on the software's last write time but including other relevant details as well.
#>
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
$execution = Measure-Command -Expression {
    $a = Get-RegInfoByLastWriteTime
}
Write-Host "Running Get-RegInfoByLastWriteTime tock $($execution.TotalMilliseconds) milliseconds and returned $($a.count) entries" -ForegroundColor Green