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

if (CheckConnectionAndUser -TestConnectionToServer "SRV-010")
{
    Write-Host "AccessToInternalDomain"
}
else
{
    Write-Host "No connection yet to company network"
}

Connect-MSGraph -ForceInteractive
Install-Module Microsoft.Graph.Intune -Force -Verbose
# Get all Apps and their id
$Apps = Get-DeviceAppManagement_MobileApps 
$Apps | select displayName, id

# Get Apps and their id, filter on App Name
$Apps = Get-DeviceAppManagement_MobileApps -Filter "contains(displayName, 'P2P')"
$Apps | select displayName, id