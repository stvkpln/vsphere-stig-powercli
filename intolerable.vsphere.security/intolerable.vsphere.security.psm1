Get-ChildItem $psScriptRoot *.ps1 | foreach { . $_.fullname }
Export-ModuleMember -Function @("Get-*","New-*","Set-*")

$stighome = $psScriptRoot
$FindingsHome = "$psScriptRoot\findings"

$stigtype = Get-VIProperty -Name STIGType -ErrorAction SilentlyContinue
if ($stigtype -ne $null) { $stigtype | Remove-VIProperty } 
New-VIProperty -ObjectType VirtualMachine -Name STIGType -Value { 
	Param ($vm)
	if ($vm.CustomFields.Item("Appliance")) {
		Switch ($vm.CustomFields.Item("Appliance")) { 
			"Yes"	{ "Appliance" }
			"No"	{ "Template" }
		}
	}
	else { "Desktop" }
}

Function Test-Checklist { 
	Param (
		[Parameter(Mandatory=$true)]
		[String]$Type
	)

	$result = @()
	Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all defined advanced options"
	$advopts = Get-AdvancedSetting -Entity $entity
	# Importing the correct STIG Checklist
	if ($Type -eq "VM")      { $checklist = Import-Csv -Path "$FindingsHome\vm-advopts.csv" }
	if ($Type -eq "VMHost")  { $checklist = Import-Csv -Path "$FindingsHome\vmhost-advopts.csv" }
	if ($Type -eq "vCenter") { $checklist = Import-Csv -Path "$FindingsHome\vcenter-advopts.csv" }

	for ($i = 0; $i -lt $checklist.count; $i++) {
		$stig = $checklist[$i]
		if ((Test-Exclusion $Exclude $stig.Finding) -eq $false) {
			$current = "Checking current value against $($stig.Finding)"
			$percent = ($i / $checklist.count)*100
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation $current -PercentComplete $percent

			# Checking the posture of the virtual machine against the checklist
			$advopt = $advopts | Where-Object { $_.Name -eq $stig.Key }
			if (!$advopt) { $impacted = "The advanced setting has no value configured" }
			$result += Test-Finding -Finding $stig.Finding -Category $stig.Category -Setting $stig.Key -Expected $stig.value -Current $advopt.Value -Impacted $impacted -Remediation $stig.Remediation
		}
	}
	$result
}

Function Test-Finding {
	Param (
		$Finding,
		$Category,
		$Setting,
		$Expected,
		$Current,
		[Alias("Notes")]
		$Impacted,
		$Remediation
	) 
	
	$exclusion = Test-Exclusion $Exclude $Finding
	if ($exclusion -eq $false) {
		Write-Progress -Activity $activity -Status "$($entity.Name)" -CurrentOperation $Setting
		if ($Expected -eq $Current) { $Compliance = $true }
		else { $Compliance = $false }

		#Creating PowerShell Object
		$result = New-Object PSObject
		Add-Member -MemberType NoteProperty -InputObject $result -Name Name 		-Value $entity.Name
		Add-Member -MemberType NoteProperty -InputObject $result -Name Type 		-Value $STIGType
		Add-Member -MemberType NoteProperty -InputObject $result -Name Finding 		-Value $Finding
		Add-Member -MemberType NoteProperty -InputObject $result -Name Category		-Value $Category
		Add-Member -MemberType NoteProperty -InputObject $result -Name Setting		-Value $Setting
		Add-Member -MemberType NoteProperty -InputObject $result -Name Expected		-Value $Expected
		Add-Member -MemberType NoteProperty -InputObject $result -Name Current 		-Value $Current
		Add-Member -MemberType NoteProperty -InputObject $result -Name Compliant	-Value $Compliance
		Add-Member -MemberType NoteProperty -InputObject $result -Name Impacted		-Value $Impacted
		Add-Member -MemberType NoteProperty -InputObject $result -Name Remediation	-Value $Remediation

		#Verifying whether to return the result
		if ($Compliance -eq $false -or $All -eq $true) {
			#Setting up the default view for the custom powershell object being returned
			$defaultProps = @("Name","Type","Finding","Category","Compliant")
			$defaultDisplayPropSet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet",[string[]]$defaultProps)
			$defaultView = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropSet)
			$result | Add-Member MemberSet PSStandardMembers $defaultView
			$result
		}
	}
}

Function Test-MultipleFindings {
	Param ($Category,$Setting,$Expected,$Current,$Impacted,$Remediation)

	foreach ($id in $StigId) {
		Test-Finding -Finding $id -Category $Category -Setting $Setting -Expected $Expected -Current $Current -Impacted $Impacted -Remediation $Remediation
	}
}

Function Test-Exclusion {
	Param (
		[Parameter(Position=0)]
		[String[]]$List,
		[Parameter(Position=1)]
		[String[]]$Finding
	)

	for ($f=0; $f -lt $Finding.count; $f++) {
		$check = $Finding[$f]
		for ($i=0; $i -lt $List.count;$i++) { 
			$exclusion = $List[$i]
			if ($exclusion -eq $check) { return $true } 
		}
	}
	return $false
}

Function Test-PortgroupOverrides {
	$policy = $VDPortgroup.ExtensionData.Config.Policy
	$finding = $false
	foreach ($property in ($policy | Get-Member -MemberType Properties).Name) {
		if ($property -eq "PortConfigResetAtDisconnect") {
			if ($policy.$property -eq $false) { $finding = $true }	
		}
		
		else {
			if ($policy.$property -eq $true) { $finding = $true }
		}
	}
	if ($finding -eq $true) { $VDPortgroup }
}

Function Export-Results {
	if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -eq $null) { 
		Write-Progress -Activity $activity -Status "Exporting results" -CurrentOperation "Creating export path"
		New-Item -Path $Path -Type Directory | Out-Null 
	}
	if (($ExportResults | Select Name -unique).Name.count -eq 1) { $file = ($ExportResults | Select-Object Name -Unique).Name.toLower() }
	else { $file = $STIGType.toLower() }
	$ExportFile = "$($Path)\$(Get-Date -format yyyy-MM-dd)_$file.csv"
	
	Write-Progress -Activity $activity -Status "Exporting results" -CurrentOperation "Exporting"
	$ExportResults | Select-Object * | Export-Csv -NoTypeInformation -Path $ExportFile

	Write-Host "Export of the STIG value check is available at: $ExportFile" -ForegroundColor Green
}