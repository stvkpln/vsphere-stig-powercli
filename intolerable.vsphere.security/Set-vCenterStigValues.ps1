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
		
		-   Category I: VCWN-06-000027
		-  Category II: VCWN-06-000001, VCWN-06-000002, VCWN-06-000003, VCWN-06-000004, VCWN-06-000005, VCWN-06-000009, VCWN-06-000010, VCWN-06-000020, VCWN-06-000022, VCWN-06-000026, VCWN-06-000028, VCWN-06-000029, VCWN-06-000030, VCWN-06-000032, VCWN-06-000033, VCWN-06-000034, VCWN-06-000035, VCWN-06-000039, VCWN-06-000040, VCWN-06-000041, VCWN-06-000042, VCWN-06-000043, VCWN-06-000045, VCWN-06-000046, VCWN-06-000047, VCWN-06-100005
		- Category III: VCWN-06-000025, VCWN-06-000031

		The following findings are not currently in scope to be remediated automatically, and will require manual remediation:

		- Category II: VCWN-06-000018, VCWN-06-000019

		See the enclosed readme.md for more information on why these have been excluded.
			
	.Example
		Set-vCenterStigResults

		Description
		-----------
		Remediates all connected vCenter Servers for applicable findings

	.Parameter VM
		Specifies virtual machine(s) to apply STIG values on. Can either be provided as a single virtual machine, an array of virtual machines, or from pipeline

	.Parameter Exclude
		A value or list of values of STIG Findings to exclude from being remediated.

	.Parameter RunAsync
		Indicates that the command returns immediately without waiting for the task to complete.
#>
Function Set-vCenterStigVaResults {
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[String[]]$Server,
		[String[]]$Exclude,
		[Switch]$RunAsync,
		[Bool]$Confirm = $true
	)

	Begin {	
		if ($Exclude -ne $null) { 
			Write-Warning "The following STIG ID's will be excluded from being checked: $($Exclude -join ', ')" 
			if ($Exclude -join ',' -match "VCWN-06-000048|VCWN-06-000049|VCWN-06-000050") { Write-Warning "STIG ID's VCWN-06-000048, VCWN-06-000049, VCWN-06-000050 cannot be mutually excluded from one another; all three will be ignored" }
		}
		$activity = "Configuring vSphere vCenter Server STIG Values"
		
		# Preconfiguring for the user prompted remediations
		$question = "Are you sure you want to proceed?"
		$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes','Update only this impacted object'))
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No','Skip updating this impacted object'))
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&All','Update all impacted objects for this finding'))
	}

	Process {
		$Servers = @()
		if ($Server -eq $null) { $Servers = $global:DefaultVIServers }
		else { 
			foreach ($vc in $Server) { 
				$vCenter = $global:DefaultVIServers | Where-Object { $_.Name -eq $vc }
				if ($vCenter) { $Servers += $vCenter }
			}
		}
		if ($Servers.count -eq 0) { Write-Error -Message "Not connected to any vCenter Servers. Please use Connect-VIServer to connect to a vCenter Server and try again." } 

		foreach ($entity in $Servers) {
			$results += Test-Checklist -Type vCenter
			<#
				VCWN-06-000021 - CAT II  - config.nfc.useSSL set to true
				VCWN-06-000023 - CAT II  - VirtualCenter.VimPasswordExpirationInDays set to 30
				VCWN-06-000024 - CAT II  - config.vpxd.hostPasswordLength set to 32
				VCWN-06-000036 - CAT III - config.log.level set to info
			#>
			if ($results) {
				$advopts = Get-AdvancedSetting -Entity $entity
				foreach ($result in $results) { 
					$advopt = $advopts | Where-Object { $_.Name -eq $result.Setting }
					if ($advopt) { $advopt | Set-AdvancedSetting -Value $result.Expected -Confirm:$false | Out-Null }
					else { New-AdvancedSetting -Entity $entity -Name $result.Setting -Value $result.Expected -Confirm:$false  | Out-Null }
				}
			}
			
			# Setting up for Alarm remediation tasks!
			$MoRef = (Get-Folder -Server $entity -Name Datacenters).Id
			$alarmMgr = Get-View -Server $entity AlarmManager
 			$alarms = Get-AlarmDefinition -Server $entity
			$events = $alarms.ExtensionData.Info.Expression.Expression

			# VCWN-06-000048, 49, 50 - CAT II - Alarm Definitions for Permissions
			$permissions = $events | Where-Object { $_.EventTypeId -match "Vim.Event.Permission" }
			if ($permissions.count -lt 3) {
				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Remediating VVCWN-06-000048, VCWN-06-000049, & VCWN-06-000050"

				# Create the alarm specification to pass into the vSphere API
				$alarmSpec = New-Object VMware.Vim.AlarmSpec
				$alarmSpec.Name = "vSphere Permission Modification"
				$alarmSpec.Description = "Automatically generated to remediate findings VVCWN-06-000048, VCWN-06-000049, & VCWN-06-000050 in the vSphere 6.0 vCenter Server STIG"
				$alarmSpec.Enabled = $true
				$alarmSpec.expression = New-Object VMware.Vim.OrAlarmExpression
				  
				# Creating the expression for each of the event types the finding(s) are looking to have defined as part of the alarm; using an array to loop through the required alarms
				$expressions = @("Vim.Event.PermissionAddedEvent","Vim.Event.PermissionRemovedEvent","Vim.Event.PermissionUpdatedEvent")
				foreach ($e in $expressions) {
					$expression = New-Object VMware.Vim.EventAlarmExpression
					$expression.EventType = $null
					$expression.eventTypeId = $e
					$expression.objectType = "Folder"
					$expression.status = "red"
					$alarmSpec.expression.expression += $expression
				}
			
				# Creating the alarm on the vCenter Server
				$alarmMgr.CreateAlarm($MoRef, $alarmSpec) | Out-Null		
			}			

			# VCWN-06-000008 - CAT III - Remote Syslog connectivity
			if ((Test-Exclusion $Exclude "VCWN-06-000008") -eq $false) {
				$syslog = $events | Where-Object { $_.EventTypeId -eq "esx.problem.vmsyslogd.remote.failure" }
				if ($syslog.count -lt 1) {
					Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Remediating VVCWN-06-000008"

					# Create the alarm specification to pass into the vSphere API
					$alarmSpec = New-Object VMware.Vim.AlarmSpec
					$alarmSpec.Name = "Host remote logging host becomes unreachable"
					$alarmSpec.Description = "Automatically generated to remediate finding VCWN-06-000008 in the vSphere 6.0 vCenter Server STIG"
					$alarmSpec.Enabled = $true
					$alarmSpec.expression = New-Object VMware.Vim.OrAlarmExpression
					  
					# Creating the expression for each of the event types the finding(s) are looking to have defined as part of the alarm
					$expression = New-Object VMware.Vim.EventAlarmExpression
					$expression.EventType = $null
					$expression.eventTypeId = "esx.problem.vmsyslogd.remote.failure"
					$expression.objectType = "HostSystem"
					$expression.status = "red"
					$alarmSpec.expression.expression += $expression
					 
					# Create alarm.
					$alarmMgr.CreateAlarm($MoRef, $alarmSpec) | Out-Null
				}
			}
			<#
				vSphere Distributed vSwitch Configuration Settings
					- VCWN-06-000007 - CAT II  - Enable Network I/O Control
					- VCWN-06-000012 - CAT III - Distributed vSwitch Health Check Enablement
					- VCWN-06-000013 - CAT II  - Promiscuous Mode Policy on Distributed Virtual Portgroup
					- VCWN-06-000014 - CAT I   - MAC Address Change Policy on Distribued Virtual Portgroups
					- VCWN-06-000015 - CAT II  - Forged Transmits Policy on Distributed Virtual Portgroup
					- VCWN-06-000016 - CAT II  - NetFlow Collector Configuration for Distributed vSwitches and Portgroups
					- VCWN-06-000017 - CAT III - Distributed Portgroup Port Override Policy Configuration
			#>
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Distributed vSwitches"
			$VDSwitches = Get-VDSwitch -Server $entity.Name | Sort Name

			# Enable Network I/O Control on all Distributed vSwitches that do not have it enabled; this will not prompt to enable on a VDS
			if ((Test-Exclusion $Exclude "VCWN-06-000007") -eq $false) {
				$nioc = $VDSwitches | Where-Object { $_.ExtensionData.Config.NetworkResourceManagementEnabled -eq $false }
				$count = 0
				foreach ($switch in $nioc) {
					Write-Progress -Activity $activity -Status "Remediating VCWN-06-000007" -CurrentOperation $switch.Name -PercentComplete (($count / $nioc.Count)*100)
					$vdsView = Get-View -Server $entity -Id $switch.Id
					$vdsView.EnableNetworkResourceManagement($true)
					$count++
				}
			}

			# Disable Distributed vSwitch Health Check on any switches where it's enabled
			Function Disable-VDSHealthCheck {
				Write-Progress -Activity $Activity -Status "Remediating VCWN-06-000012" -CurrentOperation $VDSwitch.Name -PercentComplete (($count / $ImpactedVDS.count)*100)
				$vdsView = Get-View $VDSwitch
				$spec = @()
				$spec += New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -Property @{Enable=0; Interval=1 } 
				$spec += New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -Property @{Enable=0; Interval=1 }
				if ($RunAsync) { $vdsView.UpdateDVSHealthCheckConfig_Task($spec) }
				else { $vdsView.UpdateDVSHealthCheckConfig_Task($spec) }
			}
			
			if ((Test-Exclusion $Exclude "VCWN-06-000012") -eq $false) {
				$ImpactedVDS = @()
				foreach ($VDSwitch in $VDSwitches) {
				    $enabled = $false;
				    $healthcheckconfig = $VDSwitch.ExtensionData.Config.HealthCheckConfig
				    foreach ($check in $healthcheckconfig) {
				        if ($check.enable -eq $true) { $enabled = $true }
				    }
				    if ($enabled -eq $true) { $ImpactedVDS += $VDSwitch }
				}

				$count = 0
				foreach ($VDSwitch in $ImpactedVDS) {
					$message  = "This will disable healthcheck for Distributed vSwitch '$($VDSwitch.Name)' as part of remedating finding 'VCWN-06-000012'. If you aren't 100% sure that this should be done, select 'N'"
					if ($Confirm -eq $true -and $ask -eq $true) {
						$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { Disable-VDSHealthCheck }
						# Also do this if 'A' is selected
						elseif ($decision -eq 2) { $ask = $false }
					}
					
					else { Disable-VDSHealthCheck }
					$count++
				}
			}

			# Updating Distributed Portgroup Security Policy if any of the required values are configured as $true
			Function Disable-SecurityPolicy {
				Param ($Finding,$SecurityPolicy)
				$ask = $true
				$count = 0
				$SecPol = @{ $SecurityPolicy = $false }
				foreach ($Policy in ($Policies | Where-Object { $_.$SecurityPolicy -eq $true })) {
					$pg = $Policy.VDPortgroup.Name
					Write-Progress -Activity $Activity -Status "Remediating $Finding" -CurrentOperation "Disabling '$($SecurityPolicy)' on '$($pg)'" -PercentComplete (($count / $Policies.count)*100)
					if ($Confirm -eq $true -and $ask -eq $true) {
						$message  = "This will disable the security policy '$($SecurityPolicy)' on Distributed Portgroup '$($pg)' as part of remedating finding '$($Finding)'. If you aren't 100% sure that this should be done, select 'N'"
						$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							Set-VDSecurityPolicy -Policy $Policy @SecPol -confirm:$false | Out-Null
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
					}
					else { Set-VDSecurityPolicy -Policy $Policy @SecPol -confirm:$false | Out-Null }
					$count++
				}
			}

			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Non-Uplink Distributed Portgroups"
			$VDPortgroups = Get-VDPortgroup -VDSwitch $VDSwitches | Where-Object { $_.IsUplink -eq $false } | Sort Name

			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Distribured Portgroup Security Policies"
			$Policies = Get-VDSecurityPolicy -VDPortgroup $VDPortgroups

			if ((Test-Exclusion $Exclude "VCWN-06-000013") -eq $false) { Disable-SecurityPolicy -Finding "VCWN-06-000013" -SecurityPolicy "AllowPromiscuous" }
			if ((Test-Exclusion $Exclude "VCWN-06-000014") -eq $false) { Disable-SecurityPolicy -Finding "VCWN-06-000014" -SecurityPolicy "MacChanges" }
			if ((Test-Exclusion $Exclude "VCWN-06-000015") -eq $false) { Disable-SecurityPolicy -Finding "VCWN-06-000015" -SecurityPolicy "ForgedTransmits" }

			# NetFlow Collector Configuration for Distributed vSwitches and Portgroups
			# Function to update the NetFlow configuration for a Distributed vSwitch
			Function Reset-SwitchNetFlow {
				Write-Progress -Activity $activity -Status "Remediating VCWN-06-000016" -CurrentOperation "Resetting NetFlow configuration on Distributed vSwitch $($VDSwitch.Name)" -PercentComplete (($count / $ImpactedVDS.count)*100)
				$vdsView = Get-View $VDSwitch
				$spec = New-Object VMware.Vim.VMwareDVSConfigSpec
				$spec.configversion = $vdsView.Config.ConfigVersion
				$spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig 
				$spec.IpfixConfig.CollectorIpAddress = "" 
				$spec.IpfixConfig.CollectorPort = "0" 
				$spec.IpfixConfig.ActiveFlowTimeout = "60" 
				$spec.IpfixConfig.IdleFlowTimeout = "15" 
				$spec.IpfixConfig.SamplingRate = "0" 
				$spec.IpfixConfig.InternalFlowsOnly = $False

				$vdsView.ReconfigureDvs($spec)
			}

			# Function to update the NetFlow configuration for a Distributed Portgroup
			Function Reset-PortgroupNetFlow {
				Write-Progress -Activity $activity -Status "Remediating VCWN-06-000016" -CurrentOperation "Resetting NetFlow configuration on Distributed Portgroup $($VDPortgroup.Name)" -PercentComplete (($count / $ImpactedVDP.count)*100)
				$pgView = Get-View $VDPortgroup
				$spec = New-Object VMware.Vim.DVPortgroupConfigSpec
				$spec.configversion = $pgView.Config.ConfigVersion
				$spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
				$spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
				$spec.defaultPortConfig.ipfixEnabled.inherited = $false
				$spec.defaultPortConfig.ipfixEnabled.value = $false

				$pgView.ReconfigureDVPortgroup($spec)
			}

			# Verifying whether to check for the finding and invoking 
			
			if ((Test-Exclusion $Exclude "VCWN-06-000016") -eq $false) {
				$ImpactedVDS = $VDSwitches | Where-Object { $_.ExtensionData.config.IpfixConfig.CollectorIpAddress }
				$ImpactedVDP = $VDPortgroups | Where-Object { $_.ExtensionData.Config.defaultPortConfig.ipfixEnabled.Value }

				$count = 0
				foreach ($VDSwitch in $ImpactedVDS) {
					$ask = $true
					$message  = "This will reset all NetFlow configurations for Distributed vSwitch '$($VDSwitch.Name)' as part of remedating finding 'VCWN-06-000007'. If you aren't 100% sure that this should be done, select 'N'"
					if ($Confirm -eq $true -and $ask -eq $true) {
						$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							Reset-SwitchNetFlow 
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
					}
					
					else { Reset-SwitchNetFlow }
					$count++
				}
				
				$ask = $true
				$count = 0 
				foreach ($VDPortgroup in $ImpactedVDP) {
					$message  = "This will reset all NetFlow configurations for Distributed Portgroup '$($VDPortgroup.Name)' as part of remedating finding 'VCWN-06-000007'. If you aren't 100% sure that this should be done, select 'N'"
					if ($Confirm -eq $true -and $ask -eq $true) {
						$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							Reset-PortgroupNetFlow 
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
					}
					
					else { Reset-PortgroupNetFlow }
					$count++
				}
			}
		
			# Remediating any Distributed Portgroups that have an override policy in place
			Function Reset-PortgroupOverrides {
				Write-Progress -Activity $activity -Status "Remediating VCWN-06-000017" -CurrentOperation "Removing override policies on $($VDPortgroup.Name)" -PercentComplete (($count / $ImpactedVDP.count)*100)
				$pgView = Get-View $VDPortgroup
				$spec = New-Object VMware.Vim.DVPortgroupConfigSpec 
				$spec.configversion = $pgView.Config.ConfigVersion 
				$spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy 
				$spec.Policy.BlockOverrideAllowed = $false
				$spec.Policy.IpfixOverrideAllowed = $false
				$spec.Policy.LivePortMovingAllowed = $false
				$spec.Policy.NetworkResourcePoolOverrideAllowed = $false
				$spec.Policy.PortConfigResetAtDisconnect = $true
				$spec.Policy.SecurityPolicyOverrideAllowed = $false
				$spec.Policy.ShapingOverrideAllowed = $false
				$spec.Policy.TrafficFilterOverrideAllowed = $false
				$spec.Policy.UplinkTeamingOverrideAllowed = $false
				$spec.Policy.VendorConfigOverrideAllowed = $false
				$spec.Policy.VlanOverrideAllowed = $false

				if ($RunAsync) { $pgView.ReconfigureDVPortgroup_Task($spec) }
				else { $pgView.ReconfigureDVPortgroup($spec) }
			}

			if ((Test-Exclusion $Exclude "VCWN-06-000017") -eq $false) {
				Write-Progress -Activity $activity -Status "Remediating VCWN-06-000017" -CurrentOperation "Querying for impacted Distributed Portgroups"
				$ImpactedVDP = @()
				foreach ($VDPortgroup in $VDPortgroups) { 
					$result = Test-PortgroupOverrides 
					if ($result) { $ImpactedVDP += $VDPortgroup }
				}
				$ask = $true
				$count = 0
				foreach ($VDPortgroup in $ImpactedVDP) {
					$message  = "This will reset all override policy values Distributed Portgroup '$($VDPortgroup.Name)' as part of remedating finding 'VCWN-06-000017'. If you aren't 100% sure that this should be done, select 'N'"
					if ($Confirm -eq $true -and $ask -eq $true) {
						$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
						# If 'Y' or 'A' is selected
						if ($decision -eq 0 -or $decision -eq 2) { 
							Reset-PortgroupOverrides
							if ($decision -eq 2) { $ask = $false } # Also do this if 'A' is selected
						}
					}
					
					else { Reset-PortgroupOverrides }
					$count++
				}
			}
		}
	}
}