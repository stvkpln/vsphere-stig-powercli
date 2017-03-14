<#
	.Description
		This function remediates VMware vSphere Virtual Machine 6.0 STIG values that are not set to the correct value or have not been configured

	.Synopsis
		This function updates virtual machines with the correct STIG values

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:
			2016-DEC-27 - 1.0.0; Initial release


		The following STIG Findings cannot be checked via PowerCLI, and will still require manual remediation:
			-  Category II: VMCH-06-000044
			- Category III: VMCH-06-000043

		The following findings are not currently in scope to be remediated automatically, and will require manual remediation:
			-   Category I: VMCH-06-000007
			-  Category II: VMCH-06-000030, VMCH-06-000031, VMCH-06-000032, VMCH-06-000041
			- Category III: VMCH-06-000028, VMCH-06-000040

		See the enclosed readme.md for more information on why these have been excluded.
	
	.Example
		Get-Cluster sample-cluster | Get-VM | Set-VMStigValues -Exclude VMCH-06-000035

		Description
		-----------
		Remediates all virtual machines in the 'sample-cluster' cluster for all applicable findings except for VMCH-06-000035

	.Parameter VM
		Specifies virtual machine(s) to apply STIG values on. Can either be provided as a single virtual machine, an array of virtual machines, or from pipeline

	.Parameter Exclude
		A value or list of values of STIG Findings to exclude from being remediated.

	.Parameter RunAsync
		Indicates that the command returns immediately without waiting for the task to complete.
#>
Function Set-VMStigValues {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$VM,
		[String[]]$Exclude,
		[Switch]$RunAsync
	)

	Begin {	
	 	Write-Warning "All virtual machine advanced option changes will be written persistently, but will NOT be active until virtual machine(s) are either vMotioned to a different host or a power cycle is taken."
		if ($Exclude -ne $null) { Write-Warning "The following STIG ID's will be excluded from being checked: $($Exclude -join ', ')" }
		$activity = "Configuring vSphere Virtual Machine STIG Values"
	}

	Process {
		foreach ($entity in $VM) {
			Write-Progress -Activity $activity -Status entity.Name -CurrentOperation "Initializing..."
			<# 
				VMX Advanced Option values. The following findings are applicable:
					-   Category I: VMCH-06-000005, VMCH-06-000006
					-  Category II: VMCH-06-000008, VMCH-06-000033, VMCH-06-000034, VMCH-06-000037, VMCH-06-000038, VMCH-06-000039
					- Category III: VMCH-06-000001, VMCH-06-000002, VMCH-06-000003, VMCH-06-000004, VMCH-06-000009, VMCH-06-000010, VMCH-06-000011, VMCH-06-000012, VMCH-06-000013, VMCH-06-000014, VMCH-06-000015, VMCH-06-000016, VMCH-06-000017, VMCH-06-000018, VMCH-06-000019, VMCH-06-000020, VMCH-06-000021, VMCH-06-000022, VMCH-06-000023, VMCH-06-000024, VMCH-06-000025, VMCH-06-000026, VMCH-06-000027, VMCH-06-000035, VMCH-06-000036
			#>
			$results = Test-Checklist -Type VM
			if ($results.count -gt 0) {
				$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
				foreach ($result in $results) {
					$option 			= New-Object VMware.Vim.Optionvalue
					$option.Key			= $result.Setting
					$option.value		= $result.Expected
					$spec.ExtraConfig += $option
					$update = $true
				} 
			
				Write-Progress -Activity $Activity -Status $entity.Name -CurrentOperation "Updating $($results.count) advanced options"
				if ($RunAsync) { $entity.ExtensionData.ReconfigVM_Task($spec) | Out-Null }
				else { $entity.ExtensionData.ReconfigVM($spec) }
			}

			# VMCH-06-000029 - CAT III - Connected CD/DVD Drives
			if ((Test-Exclusion $Exclude $stig.Finding) -eq $false) {
				$drives = Get-CDDrive -VM $entity | Where-Object { $_.ExtensionData.Connectable.Connected -eq $true }
				if ($drives) { 
					Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Remediating VMCH-06-000029"
					$drives | Set-CDDrive -NoMedia -Confirm:$false | Out-Null
				}
			}
		}	
	}
}

New-Alias -Force -Name Update-VMStigValues -Value Set-VMStigValues