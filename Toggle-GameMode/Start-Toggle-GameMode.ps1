if ($PSVersionTable.PSVersion -lt [Version]"7.0.0") {
	try {
		Write-Host 'Trying to launch the script using PS7 instead..'
		$file = (Get-ChildItem -Path ".\" | Select-Object Name | Where-Object { $_.Name -match 'Toggle-GameMode_.*' -and !($_.Name -match '.psbuild') } | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
		pwsh -NoProfile -NoExit -MTA -File ".\$file"
	}
	catch {
		Write-Warning 'You will get better performance using PS7 since then parallel jobs will run when stopping services'
		Start-Sleep 10
		Exit 1
	}
}
else {
	Write-Host 'Running with PS7..'
	$file = (Get-ChildItem -Path ".\" | Select-Object Name | Where-Object { $_.Name -match 'Toggle-GameMode_.*' -and !($_.Name -match '.psbuild') } | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
	pwsh -NoProfile -NoExit -MTA -File ".\$file"
}

Install-Module -Name PS2EXE -Force -Verbose -Scope CurrentUser -Confirm:$false
Import-Module -Name PS2EXE -Force -Verbose -Scope Global
Invoke-PS2EXE -inputFile .\Start-Toggle-GameMode.ps1 -outputFile .\Start-Toggle-GameMode.exe -x64 -MTA -title 'Enable-GameMode' -version '1.2' -trademark 'Harze2k' -requireAdmin -noConfigFile