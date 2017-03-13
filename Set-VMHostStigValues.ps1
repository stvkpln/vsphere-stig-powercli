<#
	.Description
		This function remediates VMware vSphere vCenter Server 6.0 STIG values that are not set to the correct value or have not been configured
	
	.Synopsis
		This function updates vCenter Servers with the correct STIG values

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:
			2016-DEC-27 - 1.0.0; Initial release


		The following STIG Findings cannot be checked via PowerCLI, and will still require manual remediation:
		
		-   Category I: ESXI-06-000011, ESXI-06-000015, ESXI-06-000071
		-  Category II: ESXI-06-000009, ESXI-06-000010, ESXI-06-000012, ESXI-06-000013, ESXI-06-000016, ESXI-06-000017, ESXI-06-000020, ESXI-06-000021, ESXI-06-000023, ESXI-06-000024, ESXI-06-000025, ESXI-06-000028, ESXI-06-000029, ESXI-06-000032, ESXI-06-000033, ESXI-06-000048, ESXI-06-000049, ESXI-06-000050, ESXI-06-000065, ESXI-06-000066, ESXI-06-000068, ESXI-06-000070, ESXI-06-100010
		- Category III: ESXI-06-000014, ESXI-06-000018, ESXI-06-000019, ESXI-06-000022, ESXI-06-000026, ESXI-06-000027, ESXI-06-000051, ESXI-06-000052, ESXI-06-000067

		The following findings are not currently in scope to be remediated automatically, and will require manual remediation:

		-   Category I: ESXI-06-000072
		-  Category II: ESXI-06-000004, ESXI-06-000007, ESXI-06-000008, ESXI-06-000038, ESXI-06-000045, ESXI-06-000046, ESXI-06-000053, ESXI-06-000056, ESXI-06-000063, ESXI-06-000064, ESXI-06-000069, ESXI-06-100004, ESXI-06-100007, ESXI-06-100038, ESXI-06-100046, ESXI-06-200004, ESXI-06-200038, ESXI-06-300004, ESXI-06-300038, ESXI-06-400004, ESXI-06-500004
		- Category III: ESXI-06-000003, ESXI-06-000037, ESXI-06-000039, ESXI-06-000040, ESXI-06-000044, ESXI-06-000054, ESXI-06-100037, ESXI-06-100039, ESXI-06-100040, ESXI-06-200037, ESXI-06-200039, ESXI-06-200040, ESXI-06-300037, ESXI-06-300039, ESXI-06-300040

		See the enclosed readme.md for more information on why these have been excluded.

	.Example
		Get-VMHost | Set-VMHostStigValues

		Description
		-----------
		Remediates all VMHost's on connected vCenter Servers for applicable findings

	.Parameter VMHost
		Specifies ESXi Host(s) to to apply STIG values on. Can either be provided as a single ESXi host, an array of ESXi hosts, or from pipeline

	.Parameter LockdownLevel
		Configures the LockdownMode level; must be set to either 'Normal' or 'Strict'

	.Parameter Exclude
		A value or list of values of STIG Findings to exclude from being remediated.

	.Parameter RunAsync
		Indicates that the command returns immediately without waiting for the task to complete.
#>
Function Set-VMHostStigValues {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
		
		# Lockdown Mode Settings
		[ValidateSet("Normal","Strict")]
		[String]$LockdownLevel,
		
		# General Settings
		[String[]]$Exclude,
		[Switch]$RunAsync,
		[Bool]$Confirm = $true
	)

	Begin {	
		$list = $Exclude -join ', '
		if ($Exclude -ne $null) { Write-Warning "The following STIG ID's will be excluded from being checked: $($list)" }
		if ($PSBoundParameters.ContainsKey("LockdownLevel") -eq $false) { Write-Warning "No value was passed to the LockdownLevel parameter; lockdown mode configuration will be skipped" }
		$activity = "Configuring vSphere VMHost STIG Values"
		
		# Preconfiguring for the user prompted remediations
		$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes','Update the setting on current item'))
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No','Skip this setting on the current item'))
		$question = "Are you sure you want to proceed?"
	}

	Process {
		foreach ($entity in $VMHost) {
			# ESXI-06-000047,100047,& 200047  - CAT I - Software Acceptance Policy for the Image Profile
			$Findings = @("ESXI-06-000047","ESXI-06-100047","ESXI-06-200047")
			if ((Test-Exclusion $Exclude $Findings) -eq $false) {
				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Initializing EsxCli Intrface"
				$esxcli = Get-EsxCli -V2 -VMHost $entity
				
				$swaccept = $esxcli.software.acceptance.get.Invoke()
				if ($swaccept -eq "CommunitySupported") { 
					Write-Progress -Activity $activity -Status "Remediating $($Findings -join ', ')" -CurrentOperation $entity.Name
					$esxcli.software.acceptance.set.Invoke(@{level = "PartnerSupported"}) | Out-Null
				}
			}

			<#
				ESXI-06-000005 - CAT II  - Set Advanced Setting Security.AccountLockFailuresto 3
				ESXI-06-000006 - CAT II  - Set Advanced Setting Security.AccountUnlockTimeto 900
				ESXI-06-000031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-100031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-200031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-300031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-400031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-500031 - CAT II  - Set Advanced Setting Security.PasswordQualityControl "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
				ESXI-06-000034 - CAT II  - Set Advanced Setting Config.HostAgent.plugins.solo.enableMobto FALSE
				ESXI-06-000043 - CAT II  - Set Advanced Setting UserVars.DcuiTimeOut to 600
				ESXI-06-100043 - CAT II  - Set Advanced Setting UserVars.DcuiTimeOut to 600
				ESXI-06-000041 - CAT II  - Set Advanced Setting UserVars.ESXiShellInteractiveTimeOut to 600
				ESXI-06-100041 - CAT II  - Set Advanced Setting UserVars.ESXiShellInteractiveTimeOut to 600
				ESXI-06-000042 - CAT II  - Set Advanced Setting UserVars.ESXiShellTimeOut to 600
				ESXI-06-100042 - CAT II  - Set Advanced Setting UserVars.ESXiShellTimeOut to 600
				ESXI-06-000002 - CAT III - Set Advanced Setting DCUI.Access to root
				ESXI-06-000030 - CAT III - Set Advanced Setting Config.HostAgent.log.level to info
				ESXI-06-000055 - CAT III - Set Advanced Setting Mem.ShareForceSalting to 2
				ESXI-06-000058 - CAT III - Set Advanced Setting Net.BlockGuestBPDU to 1
				ESXI-06-100030 - CAT III - Set Advanced Setting Config.HostAgent.log.level to info
			#>
			$results = Test-Checklist -Type VMHost
			if ($results) {
				$advoptchoices = $choices
				$advoptchoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&All','Update all advanced settings for this host'))
				
				$advopts = Get-AdvancedSetting -Entity $entity
				$ask = $true
				$count = 0 
				foreach ($result in ($results | Where-Object { $_.Finding -match "ESXI-06-00" })) {
					if ($result.count -gt 1) { $PercentComplete = ($count / $result.count)*100 }
					else { $PercentComplete = 0 }					
					if ($Confirm -eq $true -and $ask -eq $true) {
						$message  = "This will update the advanced setting '$($result.Setting)' on VMHost '$($entity.Name)' as part of remedating finding '$($result.Finding)'. If you aren't 100% sure that this should be changed, select 'N'"
						$decision = $Host.UI.PromptForChoice($message, $question, $advoptchoices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							$run = $true
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
						if ($decision -eq 1) { $run = $false }
					}
				
					else { $run = $true }

					# If we're updating the advanced option...
					if ($run -eq $true) {
						Write-Progress -Activity $Activity -Status "Remediating $($result.Finding)" -CurrentOperation "Updating $($result.Setting)" -PercentComplete $PercentComplete
						$advopt = $advopts | Where-Object { $_.Name -eq $result.Setting }
						if ($advopt) { $advopt | Set-AdvancedSetting -Value $result.Expected -Confirm:$false | Out-Null }
						else { New-AdvancedSetting -Entity $entity -Name $result.Setting -Value $result.Expected -Confirm:$false  | Out-Null }
					}
				}
			}
			<#
				ESXI-06-000059 - CAT II - Forged Transmits Policy on vSphere Standard vSwitches & Portgroups
				ESXI-06-000060 -  CAT I - MAC Address Change Policy on vSphere Standard vSwitches & Portgroup
				ESXI-06-000061 - CAT II - Promiscuous Mode Policy on vSphere Standard vSwitches & Portgroups
			#>
			Function Disable-VSSSecurityPolicy {
					Write-Progress -Activity $Activity -Status "Remediating $Finding" -CurrentOperation "Disabling '$($SecurityPolicy)' on '$($vSwitch)'" -PercentComplete $PercentComplete
					if ($Confirm -eq $true -and $ask -eq $true) {
						$message  = "This will disable the security policy '$($SecurityPolicy)' on Standard Virtual Switch '$($vSwitch)' as part of remedating finding '$($Finding)'. If you aren't 100% sure that this should be changed, select 'N'"
						$decision = $Host.UI.PromptForChoice($message, $question, $netchoices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							$run = $true
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
						if ($decision -eq 1) { $run = $false }
					}
					else { $run = $true }
					if ($run -eq $true) { Set-SecurityPolicy @SecPol -confirm:$false | Out-Null }
			}

			Function Disable-VSPSecurityPolicy {
					Write-Progress -Activity $Activity -Status "Remediating $Finding" -CurrentOperation "Disabling '$($SecurityPolicy)Inherited' on '$($pg)'" -PercentComplete $PercentComplete
					if ($Confirm -eq $true -and $ask -eq $true) {
						$message  = "This will disable the security policy '$($SecurityPolicy)' on Standard Virtual Portgroup '$($pg)' as part of remedating finding '$($Finding)'. If you aren't 100% sure that this should be changed, select 'N'"
						$decision = $Host.UI.PromptForChoice($message, $question, $netchoices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							$run = $true
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
						if ($decision -eq 1) { $run = $false }
					}
					else { $run = $true }
					if ($run -eq $true) { Set-SecurityPolicy @SecPol -confirm:$false | Out-Null }
			}

			Function Disable-SecurityPolicy {
				Param ($Finding,$SecurityPolicy)
				#Standard Virtual Switch
				$ask = $true
				$count = 0
				$Policies = $vsspolicies | Where-Object { $_.$SecurityPolicy -eq $true }
				foreach ($Policy in $Policies) {
					if ($Policies.count -gt 1) { $PercentComplete = ($count / $Policies.count)*100 }
					else { $PercentComplete = 0 }
					$count++
					$vSwitch = $Policy.VirtualSwitch.Name
					$SecPol = @{ VirtualSwitchPolicy = $Policy; $SecurityPolicy = $false }
					Disable-VSSSecurityPolicy
				}
			
				#Standard Virtual Portgroup
				$ask = $true
				$count = 0
				$Policies = $vsppolicies | Where-Object { $_."$($SecurityPolicy)Inherited" -eq $false }
				foreach ($Policy in $Policies) {
					if ($Policies.count -gt 1) { $PercentComplete = ($count / $Policies.count)*100 }
					else { $PercentComplete = 0 }
					$count++
					$pg = $Policy.VirtualPortgroup.Name
					$SecPol = @{VirtualPortGroupPolicy = $Policy; "$($SecurityPolicy)Inherited" = $true }					
					Disable-VSPSecurityPolicy
				}
			}

			# STIG Findings that rely on network configurations
			$netchoices = $choices
			$netchoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&All','Update all impacted values for this finding'))
			$000059 = Test-Exclusion $Exclude "ESXI-06-000059"
			$000060 = Test-Exclusion $Exclude "ESXI-06-000060"
			$000061 = Test-Exclusion $Exclude "ESXI-06-000061"
			
			if ($000059 -eq $false -or $000060 -eq $false -or $000061 -eq $false) { 
				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard vSwitches"
				$VSSwitches = Get-VirtualSwitch -Standard -VMHost $entity 
			}

			if ($VSSwitches -ne $null) {
				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard vSwitch Security Policies"
				$vsspolicies = Get-SecurityPolicy -VirtualSwitch $VSSwitches

				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard Portgroups"
				$VSPortgroups = Get-VirtualPortgroup -VirtualSwitch $VSSwitches

				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard Portgroup Security Policies"
				$vsppolicies = Get-SecurityPolicy -VirtualPortGroup $VSPortgroups
			}
			# Function to simplify Policy Checking

			if ($000059 -eq $false) { Disable-SecurityPolicy -Finding "ESXI-06-000059" -SecurityPolicy "ForgedTransmits" } 
			if ($000060 -eq $false) { Disable-SecurityPolicy -Finding "ESXI-06-000060" -SecurityPolicy "MacChanges" }
			if ($000061 -eq $false) { Disable-SecurityPolicy -Finding "ESXI-06-000061" -SecurityPolicy "AllowPromiscuous" }#>
		
			# Services on the Host that need to be disabled per the STIG
			$services = Get-VMHostService -VMHost $entity

			# ESXI-06-000035,ESXI-06-100035, & ESXI-06-200035 - CAT II - Checking whether SSH is Enabled
			$Findings = @("ESXI-06-000035","ESXI-06-100035","ESXI-06-200035")
			if ((Test-Exclusion $Exclude $Findings) -eq $false) {
				$Status = "Remediating findings $($Findings -join ', ')"
				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Querying for the SSH service on $($entity.Name) "
				$service = $services | Where-Object { $_.Label -eq "SSH" }

				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Stopping SSH service on $($entity.Name)"
				Stop-VMHostService -HostService $service -Confirm:$false | Out-Null

				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Setting SSH service policy to 'off' on $($entity.Name)"
				Set-VMHostService -HostService $service -Policy off -Confirm:$false | Out-Null
			}

			# ESXI-06-000036 - CAT II - Checking whether Local Shell is Enabled
			if ((Test-Exclusion $Exclude "ESXI-06-000036") -eq $false) {	
				$Status = "Remediating finding ESXI-06-000036"
				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Querying for the Local Shell service on $($entity.Name) "
				$ervice= $services | Where-Object { $_.Label -eq "ESXi Shell" }

				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Stopping Local Shell service on $($entity.Name)"
				Stop-VMHostService -HostService $service -Confirm:$false | Out-Null

				Write-Progress -Activity $activity -Status $Status -CurrentOperation "Setting Local Shell service policy to 'off' on $($entity.Name)"
				Set-VMHostService -HostService $service -Policy off -Confirm:$false | Out-Null
			}
		
			# ESXI-06-000001 & ESXI-06-100001 - CAT II - Lockdown Mode Enablement Checking
			if ((Test-Exclusion $Exclude $Findings) -eq $false -and $PSBoundParameters.ContainsKey("LockdownLevel") -eq $true) {
				$Findings = @("ESXI-06-000001","ESXI-06-100001")
				$expectedMode = "lockdown$($LockdownLevel)".toLower()
				$vCenter = $entity.uid.split(@("@",":"))[1]
				
				$HostAccessManager = Get-View -Server $vCenter $entity.ExtensionData.ConfigManager.HostAccessManager
				$currentMode = $HostAccessManager.LockdownMode.toString().toLower()
				if ($currentMode -ne $expectedMode) { 
					Write-Progress -Activity $activity -Status "Remediating findings $($Findings -join ', ')" -CurrentOperation "Setting Lockdown Mode to: $($LockdownLevel)"
					$HostAccessManager.ChangeLockdownMode($expectedMode)
				}
			}
		}
	}


}