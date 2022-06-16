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
{   Param(
        $AppID,
        [switch]$Quiet
    )

    If ($AppID.Length -ge 37)
    {
        $AppID = $AppID.Substring(0,36)
        $AppID = $AppID+'*'
    }
    elseif($AppID.Length -eq 36)
    {
        $AppID = $AppID+'*'    
    }
    else 
    {
        if(($Quiet.isPresent) -eq $false)
        {
            Return "AppID needs to be 36 chars long."
        }
    }
    $Path = "HKLM:SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    $UserObjectID = (get-ChildItem -Directory $Path -Depth 0 | Select-Object PSChildName | Where-Object {$_.PSChildName -match '([\w\-]+)' -and ($_.PSChildName) -notmatch '00000000-0000-0000-0000-000000000000' -and ($_.PSChildName) -notmatch 'Reporting'}).PSChildName
    $Return = (Get-ChildItem -Path $Path\$UserObjectID) -match $AppID | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    if(($Quiet.isPresent) -eq $false)
    {
        $return
    }
}

if (CheckConnectionAndUser -TestConnectionToServer "SRV-010")
{
    Write-Host "AccessToInternalDomain"
    Exit 0
}
else
{
    Write-Host "No connection yet to company network"
    ReRunIntuneDeployment -AppID '00dfed0d-dfc2-48ad-b031-2f3d0e750843' -Quiet ## Remove the regvaule for $AppID so it will rerun quicker.
    Exit 0
}
