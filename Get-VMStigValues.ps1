<#
	.Description
		This function checks STIG values from the module location for virtual machines and returns a list of non-compliant values

	.Synopsis
		This function checks virtual machines STIG compliance values

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:
			2016-DEC-27 - 1.0.0; Initial release


		The following STIG Findings cannot be checked via PowerCLI, and will require being checked manual:

		-  Category II: VMCH-06-000044
		- Category III: VMCH-06-000043

		See the enclosed readme.md for more information on why these have been excluded.

	.Example
		$results = Get-VM | Get-VMStigValues -Exclude VMCH-06-000035
		
		Description
		-----------
		Runs the STIG check for all documented findings except for 'VMCH-06-000035'

	.Example
		$results = Get-VM generic-vm2 | Get-VMStigValues -All
		
		Description
		-----------
		Runs the STIG check for all documented findings on virtual machine 'generic-vm2' and returns all results into a variable $results for review

	.Parameter VM
		Specifies virtual machine(s) to check STIG values on. Can either be provided as a single virtual machine, an array of virtual machines, or from pipeline

	.Parameter All
		This will return the results for all values, not just those that were non-compliant (not recommended for more than a single VM)

	.Parameter Exclude
		A list of findings to be excluded from being checked / logged as part of the STIG check

	.Parameter Export
		Indicates that the results should be exported to a file rather than displayed in the shell window. Exported results will include all fields

	.Parameter Path
		The path where the exported results should be placed. File name will be generated automatically
#>
Function Get-VMStigValues { 
	[CmdletBinding(DefaultParameterSetName="Normal")]
	Param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$VM,

		[Parameter(ParameterSetName="Exclusions")]
		[String[]]$Exclude,
		
		[Parameter(ParameterSetName="AllResults")]
		[Switch]$All,

		[Switch]$Export,
		[String]$Path = "c:\temp"
	)

	Begin {
		if ($Exclude -ne $null) { Write-Warning "The following STIG ID's will be excluded from being checked: $($Exclude -join ', ')" }
	 	$activity = "Checking vSphere 6.0 Virtual Machine STIG"
	 	$STIGType = "VM"
	 	if ($Export) { $ExportResults = @() }
	 }

	Process {
		foreach ($entity in $VM) {
			$results = @()
			<# 
				VMX Advanced Option Hardening. The following findings are applicable:
					-   Category I: VMCH-06-000005, VMCH-06-000006
					-  Category II: VMCH-06-000008, VMCH-06-000033, VMCH-06-000034, VMCH-06-000037, VMCH-06-000038, VMCH-06-000039
					- Category III: VMCH-06-000001, VMCH-06-000002, VMCH-06-000003, VMCH-06-000004, VMCH-06-000009, VMCH-06-000010, VMCH-06-000011, VMCH-06-000012, VMCH-06-000013, VMCH-06-000014, VMCH-06-000015, VMCH-06-000016, VMCH-06-000017, VMCH-06-000018, VMCH-06-000019, VMCH-06-000020, VMCH-06-000021, VMCH-06-000022, VMCH-06-000023, VMCH-06-000024, VMCH-06-000025, VMCH-06-000026, VMCH-06-000027, VMCH-06-000035, VMCH-06-000036, VMCH-06-000040
			#>
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Advanced Settings"
			$results = Test-Checklist -Type VM
			
			# VMCH-06-000007 - CAT I- Check for independent non-persistent disks
			$disks = Get-HardDisk -VM $entity | Where-Object { $_.Persistence -ne "Persistent" }
			$results += Test-Finding -Finding "VMCH-06-000007" -Category "I" -Setting "Independent Non-Persistent Disks" -Expected 0 -Current $disks.count -Remediation "Manual"

			# VMCH-06-000028 - CAT III- Check for floppy drives / devices
			$floppy = Get-FloppyDrive -VM $entity
			$results += Test-Finding -Finding "VMCH-06-000028" -Category "II" -Setting "Floppy Drives" -Expected 0 -Current $floppy.count -Remediation "Manual"
		
			# VMCH-06-000029 - CAT III - Connected CD/DVD Drives
			$drives = Get-CDDrive -VM $entity | Where-Object { $_.ExtensionData.Connectable.Connected -eq $true}
			$results += Test-Finding -Finding "VMCH-06-000029" -Category "III" -Setting "Connected CD/DVD Drives" -Expected 0 -Current $drives.count -Remediation "Automated"

			# VMCH-06-000030, VMCH-06-000031, & VMCH-06-000032 - CAT II- Hardware Checks for Parallel & Serial Devices
			$devices = $entity.ExtensionData.Config.Hardware.Device.DeviceInfo
			$parallel = $devices | Where-Object { $_.Label -match "Parallel" }
			$serial = $devices | Where-Object { $_.Label -match "Serial" }
			$usb = $devices | Where-Object { $_.Label -match "USB" }
			$results += Test-Finding -Finding "VMCH-06-000030" -Category "II" -Setting "Parallel Devices" -Expected 0 -Current $parallel.count -Remediation "Manual"
			$results += Test-Finding -Finding "VMCH-06-000031" -Category "II" -Setting "Serial Devices"   -Expected 0 -Current $serial.count -Remediation "Manual"
			$results += Test-Finding -Finding "VMCH-06-000032" -Category "II" -Setting "USB Devices"      -Expected 0 -Current $usb.count -Remediation "Manual"

			# VMCH-06-000041 - CAT II - dvFilter API Check
			$dvfilters = $advopts | Where-Object { $_.Name -match "ethernet" -and $_.Name -match "filter" }
			$results += Test-Finding -Finding "VMCH-06-000041" -Category "II " -Setting "dvFilter Network API" -Expected 0 -Current $dvfilters.count -Remediation "Manual"

			# Returning the results of the virtual machine check
			if ($Export) { $ExportResults += $results }
			else { $results }
		}
	}

	End { 
		if ($Export) { Export-Results }
	}
}