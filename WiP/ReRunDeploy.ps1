Function CurrentUser
{
	$LoggedInUser = (Get-CimInstance -ClassName Win32_ComputerSystem).Username | Out-String
    $LoggedInUserUpn = $LoggedInUser
    try
    {
        $LoggedInUser = $LoggedInUser.split("\")
        $LoggedInUserUpn = $LoggedInUserUpn.split("@")
	    if ("" -ne $LoggedInUser -or ($LoggedInUserUpn) -ne "")
	    {
		    if ($LoggedInUser[0].TrimEnd() -eq "internal")
		    {     
			    $LoggedInUser = $LoggedInUser[1].TrimEnd()
			    Return $LoggedInUser
		    }
		    elseif ($LoggedInUserUpn[1].TrimEnd() -match "aimopark*")
		    {
                $LoggedInUserUpn = $LoggedInUserupn[0]+'@'+$LoggedInUserupn[1]
			    Return $LoggedInUserUpn  
		    }
            else
            {
                Return $false  
            }
	    }
	    else
	    {
		    Return $false
	    }
    }
    catch
    {
        Return $false
    }
}

Function CheckConnectionAndUser
{
	Param([string]$TestConnectionToServer)
	
    $currUser = CurrentUser #Current logged in user
    try
    {
        if($currUser -ne $false -and (Test-Path -Path "\\$($TestConnectionToServer)\Public\" -PathType Container -ErrorAction Stop -WarningAction Stop) -eq $true)
	    {
            Return $true
	    }
	    else 
	    {
            Return $false
	    }
    }
    catch
    {
        Return $false
    }
}

Function ReRunIntuneDeployment
{
        $a = '00dfed0d-dfc2-48ad-b031-2f3d0e750843_3'
        $a = $a.Replace('_*','').Replace('*','')
        $a = $a -replace '^([_0-9])$'
    Param($AppID)
    $Path = "HKLM:SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    $UserObjectID = (get-ChildItem -Directory $Path -Depth 0 | Select-Object PSChildName | Where-Object {$_.PSChildName -match '([\w\-]+)' -and ($_.PSChildName) -notmatch '00000000-0000-0000-0000-000000000000' -and ($_.PSChildName) -notmatch 'Reporting'}).PSChildName
    $a = $a.Replace('_*','').Replace('_','')
    $App = $a.Substring(0, $a.IndexOf('[*_]')) #.Substring(0, $a.IndexOf('*'))
    $Return = (Get-ChildItem -Path $Path\$UserObjectID) -match $App | Remove-Item -Recurse -Force -WhatIf -Verbose
    $return
}
ReRunIntuneDeployment -AppID '00dfed0d-dfc2-48ad-b031-2f3d0e750843*'

if (CheckConnectionAndUser -TestConnectionToServer "SRV-010")
{
    Write-Host "AccessToInternalDomain"
}
else
{
    Write-Host "No connection yet to company network"
}



