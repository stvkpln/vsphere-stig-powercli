<#
	.Description
		The New-IAVA function creates a new VMware Update Manager Patch Baseline based on the provided inputs on all connected vCenter Servers

	.Synopsis
		Used to create Update Manager Patch baselines for IAVA's

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:
			2016-DEC-27 - 1.0.0; Initial release

	.Parameter Name
		The name of the IAVA, as provided by CYBERCOM

	.Parameter VMSA
		The identifier of the VMware Security Advisory

	.Parameter Patches
		The VMware Patch ID's required for compliance with the IAVA / VMSA
#>

Function New-IAVA {
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VMSA,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Patches
	)

	# Checking if a specific vCenter Server was specified
	$vCenters = $global:DefaultVIServers
	if ($vCenters.count -lt 1) { Write-Error "Not connected to any vCenter Servers. Please connect to at least one using the Connect-VIServer cmdlet." }
	
	else {
		# Prepping variables to be used later on in the loop function
		$Activity = "Creating VMware Update Manager Baseline for IAVA $($Name)"
		$Description = "As referenced from VMware Security Advisory $vmsa (https://www.vmware.com/security/advisories/$vmsa)"
		
		Foreach ($vc in $vCenters) {
			Write-Progress -Activity $Activity -Status $vc.Name -CurrentOperation "Checking whether the baseline exists"
			$baseline = Get-PatchBaseline -Server $vc -Name $name -ErrorAction SilentlyContinue
			
			if ($baseline -eq $null) {
				Write-Progress -Activity $activity -Status $vc.Name -CurrentOperation "Querying for all required patches from Update Manager Repository"
				$repopatches = $repopatches = Get-Patch -Server $vc -SearchPhrase $Patches

				if ($repopatches.count -ge 1) {
					Write-Progress -Activity $activity -Status $vc.Name -CurrentOperation "Creating Update Manager Baseline"
					New-PatchBaseline -Server $vc -Name "Security - $($Name)" -Description $Description -TargetType Host -Static -IncludePatch $repopatches 
				}
		
				else { Write-Error "No patches found using filter $($Patches) on target vCenter Server $($vc.Name); baseline was not created."}
			}
		
			else { Write-Warning "A baseline for IAVA $($Name) has already been created on target vCenter Server $($vc.Name); skipping creation." }
		}
	}
}