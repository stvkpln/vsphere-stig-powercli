<#
	.Description
		This cmdlet checks STIG values from the module location for virtual machines and returns a list of non-compliant values

	.Synopsis
		This cmdlet checks virtual machines STIG compliance values

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:
			2016-DEC-27 - 1.0.0; Initial release


		The following STIG Findings cannot be checked via PowerCLI, and will require being checked manual:
		
		-   Category I: ESXI-06-000011, ESXI-06-000015, ESXI-06-000071
		-  Category II: ESXI-06-000009, ESXI-06-000010, ESXI-06-000012, ESXI-06-000013, ESXI-06-000016, ESXI-06-000017, ESXI-06-000020, ESXI-06-000021, ESXI-06-000023, ESXI-06-000024, ESXI-06-000025, ESXI-06-000028, ESXI-06-000029, ESXI-06-000032, ESXI-06-000033, ESXI-06-000048, ESXI-06-000049, ESXI-06-000050, ESXI-06-000065, ESXI-06-000066, ESXI-06-000068, ESXI-06-000070, ESXI-06-100010
		- Category III: ESXI-06-000014, ESXI-06-000018, ESXI-06-000019, ESXI-06-000022, ESXI-06-000026, ESXI-06-000027, ESXI-06-000051, ESXI-06-000052, ESXI-06-000067
  
		See the enclosed readme.md for more information on why these have been excluded.

	.Example
		$results = Get-VMHost generic-host1.domain.local | Get-VMHostStigValues -NTPServers "ntp1.domain.local","ntp2.domain.local"
		
		Description
		-----------
		Runs the STIG check for all documented findings on generic-host1, using ntp1.domain.local and ntp2.domain.local as the authorized time sources

	.Example
		$results = Get-VMHost | Get-VMHostStigValues -Exclude ESXI-06-000053
		
		Description
		-----------
		Runs the STIG check for all documented findings except 'ESXI-06-000053' on all attached VMHost's

	.Parameter VMHost
		Specifies ESXi Host(s) to check STIG values on. Can either be provided as a single ESXi host, an array of ESXi hosts, or from pipeline

	.Parameter UpdateBaselines
		If this switch is passed, an Update Manager scan will be initiated and the overall check of each host will be delayed due to the scan not being able to be run asynchronously

	.Parameter NTPServers
		An array of authorized NTP Servers to check for in STIG Findings: ESXI-06-000046 & ESXI-06-100046. If values are not provided, or a default is not set in the .ps1 file, these findings will be skipped and a warning will be issued

	.Parameter IPv6
		Set to $false by default; only change if IPv6 is being used on the hosts that are part of the review

	.Parameter LockdownExceptionUsers
		An array of allowed user accounts that are exempted from Lockdown Mode within the host's whitelist

	.Parameter All
		This will return the results for all values, not just those that were non-compliant (not recommended for more than a single VM)

	.Parameter Exclude	
		A list of findings to be excluded from being checked / logged as part of the STIG check

	.Parameter Export
		Indicates that the results should be exported to a file rather than displayed in the shell window. Exported results will include all fields

	.Parameter Path
		The path where the exported results should be placed. File name will be generated automatically
#>
Function Get-VMHostStigValues {
	[CmdletBinding(DefaultParameterSetName="Normal")]
	Param (
		# Available to all Parameter Sets
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
		[Switch]$UpdateBaselines,
		[String[]]$NTPServers,
		[Bool]$IPv6 = $false,
		[String[]]$LockdownExceptionUsers,
		[Switch]$Export,
		[String]$Path = "c:\temp",

		[Parameter(ParameterSetName="Exclusions")]
		[String[]]$Exclude,
		
		[Parameter(ParameterSetName="AllResults")]
		[Switch]$All
	)

	Begin { 
		if ($Exclude -ne $null) { Write-Warning "The following STIG ID's will be excluded from being checked: $($Exclude -join ', ')" }
		if ($NTPServers -eq $null) { Write-Warning "The following findings will flag as non-compliant due to the -NTPServers flag having no values passed: ESXI-06-000046, ESXI-06-100046. Please read the notes provided in the impacted field for the hosts!" }
		$activity = "Checking vSphere 6.0 ESXi Host STIG"
		$STIGType = "VMHost"
		if ($Export) { $ExportResults = @() }
	}

	Process {
		foreach ($entity in $VMHost) {
			$results = @()
			
			# ESXI-06-000072 - CAT I - Update Manager Baseline State
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying Update Manager Baseline Compliance"
			if ($UpdateBaselines) { Test-Compliance -Entity $entity }
			$vumStatus = Get-Compliance -Entity $entity | Where-Object  { $_.Status -ne "Compliant" }

			if ($vumStatus.count -ne 0) { $baselines = $vumStatus.Baseline.Name -join ', ' }
			Test-Finding -Finding "ESXI-06-000072" -Category "I" -Setting "Update Manager Baseline Status" -Expected 0 -Current $vumStatus.count -Impacted $baselines -Remediation "Manual"

			# STIG Findings that rely on using esxcli for value checking
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Initializing EsxCli Intrface"
			$esxcli = Get-EsxCli -V2 -VMHost $entity

			# ESXI-06-000047,100047,& 200047  - CAT I - Software Acceptance Policy for the Image Profile
			$StigID = @("ESXI-06-000047","ESXI-06-100047","ESXI-06-200047")
			$swaccept = $esxcli.software.acceptance.get.Invoke()
			if ($swaccept -eq "CommunitySupported") { $check = $false }
			else { $check = $true }
			$results +=  Test-MultipleFindings -Category "I" -Setting "Image Profile Software Acceptance Policy" -Expected $true -Current $check -Remediation "Automated"

			# ESXI-06-000045 - CAT II - Persistent Log Storage Location
			$syslog = $esxcli.system.syslog.config.get.Invoke()
			$results += Test-Finding -Finding "ESXI-06-000045" -Category "II" -Setting "Persistent Log Storage Location" -Expected $true -Current $syslog.LocalLogOutputIsPersistent -Remediation "Manual"

			# ESXI-06-000053 - CAT II - Proper SNMP Configuration Checks
			$check = $false; $notes = $null
			$snmp = $esxcli.system.snmp.get.Invoke()
			if ($snmp.privacy -ne $null -and $snmp.authentication -ne $null) {
				if ($snmp.v3targets -ne $null) { $check = $true }
				else { $notes = "SNMPv3 Targets not configured" }
			}

			else {
				if ($snmp.communities -ne $null -and $snmp.communities -ne "public") { $check = $true }
				else { $notes = "SNMP Community string is set to 'public'" }
			}

			$results += Test-Finding -Finding "ESXI-06-000053" -Category "II" -Setting "Proper SNMP Configuration" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# ESXI-06-000044 - CAT III - Kernel Core Dump Configuration
			$check = $false; $notes = $null
			$partition = $esxcli.system.coredump.partition.get.Invoke()
			$netdump = $esxcli.system.coredump.network.get.Invoke()

			if ($partition.Active -ne $null -and $partition.Active -eq $partition.Configured) {
				$check = $true
				$notes = "Using a local partition for the core dump location"
			}

			elseif ($netdump.Enabled -eq $true -and $netdump.HostVnic -ne $null -and $netdump.NetworkServerIP -ne $null -and $netdump.NetworkServerPort -ne 0) { 
				$check = $true
				$notes = "Using a network location for core dump storage"
			}

			if ($check -eq $false) { $notes = "Coredump configuration is not in place" }
			$results += Test-Finding -Finding "ESXI-06-000044" -Category "III" -Setting "Kernel Core Dump Configuration" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# STIG Findings that rely on network configurations
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard vSwitches"
			$VSSwitches = Get-VirtualSwitch -Standard -VMHost $entity
			
			if ($VSSwitches -ne $null) {
				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard vSwitch Security Policies"
				$vsspolicies = Get-SecurityPolicy -VirtualSwitch $VSSwitches

				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard Portgroups"
				$VSPortgroups = Get-VirtualPortgroup -VirtualSwitch $VSSwitches

				Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Standard Portgroup Security Policies"
				$vsppolicies = Get-SecurityPolicy -VirtualPortGroup $VSPortgroups
			}
			# Function to simplify Policy Checking
			Function Test-StandardNetPolicy {
				Param ($Finding,$Category,$Setting,$Policy)
				$swPol = $vsspolicies | Where-Object { $_.$Policy -eq $true }
				$pgPol = $vsppolicies | Where-Object { $_."$($Policy)Inherited" -eq $false }

				Test-Finding -Finding $Finding -Category $Category -Setting "$($Setting) Policy: Virtual Switch"    -Expected 0 -Current $swPol.count -Impacted ($swPol.VirtualSwitch.Name -join ', ') -Remediation "Automated"
				Test-Finding -Finding $Finding -Category $Category -Setting "$($Setting) Policy: Virtual Portgroup" -Expected 0 -Current $pgPol.count -Impacted ($pgPol.VirtualPortGroup.Name -join ', ') -Remediation "Automated"
			}

			# ESXI-06-000060 - CAT I - MAC Address Change Policy on vSphere Standard vSwitches & Portgroup
			$results += Test-StandardNetPolicy -Finding "ESXI-06-000060" -Category "I" -Setting "MAC Address Change" -Policy "MacChanges"

			# ESXI-06-000059, 61 - CAT II - Forged Transmits & Promiscuous Mode Policy on vSphere Standard vSwitches & Portgroups
			$results += Test-StandardNetPolicy -Finding "ESXI-06-000059" -Category "II" -Setting "Forged Transmit" -Policy "ForgedTransmits"
			$results += Test-StandardNetPolicy -Finding "ESXI-06-000061" -Category "II" -Setting "Promiscuous Mode" -Policy "AllowPromiscuous"

			# ESXI-06-000063 & ESXI-06-000064 - CAT II - Native VLAN & Virtual Guest Tagging Portgroup Check
			function Test-SPG {
				Param ($Finding,$Setting,$VlanId)
				$check = $VSPortgroups | Where-Object { $_.VlanId -eq $VlanId }
				Test-Finding -Finding $Finding -Setting "$($Setting) tagging on virtual portgroup(s)" -Category "II" -Expected 0 -Current $check.count -Impacted ($check.Name -join ', ') -Remediation "Manual"
			}

			$results += Test-SPG -Finding "ESXI-06-000063" -Setting "Native VLAN" -VlanId 0
			$results += Test-SPG -Finding "ESXI-06-000064" -Setting "Guest VLAN" -VlanId 4095

			# ESXI-06-000054 - CAT III - iSCSI Target Authentication
			$notes = $null
			$iscsi = Get-VMHostHba -VMHost $entity -Type iscsi
			if ($iscsi.count -eq 0) { $check = $true }
			else {
				$check = $false
				$notes = "iSCSI is configured on this host, so the check must be conducted manually due to verifying that each host is using a unique CHAP secret."
			}
			Test-Finding -Finding "ESXI-06-000054" -Setting "iSCSI Configuration" -Category "III" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# ESXI-06-000056 - CAT II - Enabled Firewall rules with all IP's enabled
			$rules = Get-VMHostFirewallException -VMHost $entity | Where-Object { $_.Enabled -eq $true }
			$badrules = @()
			foreach ($rule in $rules) {
				if ($rule.ExtensionData.AllowedHosts.AllIp -eq $true) { $badrules += $rule.Name }
			}
			
			Test-Finding -Finding "ESXI-06-000056" -Category "II" -Setting "Enabled Firewall Rules Without Restrictions" -Expected 0 -Current $badrules.count -Impacted ($badrules -join ', ') -Remediation "Manual"

			# ESXI-06-000057 - CAT II - VMHost Default Firewall Policy
			$defaultPolicy = Get-VMHostFirewallDefaultPolicy -VMHost $entity
			$check = $true
			$enabledPolicy = @()
			if ($defaultPolicy.IncomingEnabled -eq $true) {
				$enabledPolicy += "Incoming"
				$check = $false
			}

			if ($defaultPolicy.OutgoingEnabled -eq $true) {
				$enabledPolicy += "Outgoing"
				$check = $false
			}

			Test-Finding -Finding "ESXI-06-000057" -Category "II" -Setting "Default Firewall Policy" -Expected 0 -Current $enabledPolicy.count -Impacted ($enabledPolicy -join ', ') -Remediation "Automated"
			
			# Checking service enablement
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all VMHost Services"
			$services = Get-VMHostService -VMHost $entity

			# ESXI-06-000035,ESXI-06-100035, & ESXI-06-200035 - CAT II - Checking whether SSH is Enabled
			$StigID = @("ESXI-06-000035","ESXI-06-100035","ESXI-06-200035")
			$ssh = $services | Where-Object { $_.Label -eq "SSH" }
			$results += Test-MultipleFindings -Category "II" -Setting "ESXi Host Service: SSH" -Expected $false -Current $ssh.Running -Remediation "Automated"

			# ESXI-06-000036 - CAT II - Checking whether Local Shell is Enabled
			$shell = $services | Where-Object { $_.Label -eq "ESXi Shell" }
			$results += Test-Finding -Finding "ESXI-06-000036" -Category "II" -Setting "ESXi Host Service: ESXi Shell" -Expected $false -Current $shell.Running -Remediation "Automated"
			
			# ESXI-06-000046 & ESXI-06-100046 - CAT II - NTP Enabled & Configured
			$StigID = @("ESXI-06-000046","ESXI-06-100046")
			$notes = $null
			
			# Performing the check on whether the NTP Daemon is started and set to start a boot
			$ntpd = $services | Where-Object { $_.Label -eq "NTP Daemon" }
			if ($ntpd.Running -eq $true -and $ntpd.Policy -eq "on") { $ntpdcheck = $true }
			else { 
				$ntpdcheck = $false 
				$notes = "NTP Service is not properly configured. Ensure it is running and set to start at boot. "
			}
			
			# Performing the check to confirm whether the NTP Daemon is configured with valid servers; only occurs if -NTPServers is passed values
			if ($NTPServers.count -eq 0) { $check = $false }
			else {
				$valid = 0
				$invalid = @()
				$configured = Get-VMHostNtpServer -VMHost $entity
				foreach ($source in $sources) {
					$confirmed = $false
					foreach ($NTPServer in $NTPServers) {
						if ($NTPServer -eq $source) { $confirmed = $true }
					}
					if ($confirmed -eq $false) { $invalid += $source }
				}
				if ($valid -eq $sources.count) { $sourcecheck = $true }
				else { 
					$sourcecheck = $false 
					$notes += "The following configured NTP Servers are not part of the list provided via the -NTPServers parameter: ($invalid -join ', ')"
				}
			}

			# Checking the results; setting remediation to manual, as this is something that *should* be handled in a host profile.....
			if ($ntpdcheck -eq $true -and $sourcecheck -eq $true) { $check = $true }
			else { $check = $false }
			$results +=  Test-MultipleFindings -Category "II" -Setting "NTP Enabled and Configured with authoratative sources" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"
			
			# ESXI-06-000069 - CAT II - IPv6 Enabled
			$notes = "Enabling/Disabling of IPv6 requires a reboot, thus necessitating this task to be remediated manually"
			Test-Finding -Finding "ESXI-06-000069" -Category "II" -Setting "IPv6 Configuration" -Expected $IPv6 -Current (Get-VMHostNetwork -VMHost $entity).IPv6Enabled -Impacted $notes -Remediation "Manual"

			#Lockdown Mode View Setup
			$vCenter = $entity.uid.split(@("@",":"))[1]
			$HostAccessManager = Get-View -Server $vCenter $entity.ExtensionData.ConfigManager.HostAccessManager

			# ESXI-06-000001 & ESXI-06-100001 - CAT II - Lockdown Mode Enablement Checking
			$StigID = @("ESXI-06-000001","ESXI-06-100001")
			$LockdownMode = $HostAccessManager.LockdownMode.toString()
			if ($LockdownMode -eq "lockdownDisabled") { $check = $false; }
			else { $check = $true }
			$results +=  Test-MultipleFindings -Category "II" -Setting "Lockdown Mode Enablement" -Expected $true -Current $check -Remediation "Automated"

			# ESXI-06-000003 - CAT III - Lockdown Mode Exceptions
			$notes = $null
			if ($LockdownMode -eq "lockdownDisabled") { 
				$check = $true
				$notes = "Skipped because Lockdown mode is not enabled on this host."
				Write-Warning "Lockdown Exceptions check was skipped because Lockdown Mode is not enabled on $($entity.name)"
			}
			
			else {
				$LockdownExceptions = $HostAccessManager.QueryLockdownExceptions()
				$undeclared = 0
				if ($LockdownExceptionUsers.count -eq 0 -and $LockdownExceptions.count -eq 0) { $check = $true }
				if ($LockdownExceptionUsers.count -gt 0 -and $LockdownExceptions.count -eq 0) { 
					$check = $true
					$notes = "Lockdown exceptions list is empty, but the following users were declared as valid: $($LockdownExceptionUsers -join ', ')"
				}

				if ($LockdownExceptionUsers.count -eq 0 -and $LockdownExceptions.count -gt 0) { 
					$check = $true
					$notes = "No accepted lockdown users were provided, but the exception list is not empty.  The following users are currently in the exceptions list: $($LockdownExceptions -join ', ')"
				}
			}
			
			$results += Test-Finding -Finding "ESXI-06-000003" -Category "III" -Setting "Authorized Lockdown Exception Users" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# Checking all findings with Advanced Settings that have static values for checking
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Advanced Settings"
			$advopts = Get-AdvancedSetting -Entity $entity
			$results += Test-Checklist -Type VMHost

			# ESXI-06-000004, 100004, 200004, 300004, 400004, & 500004 - CAT II - Remote Syslog Configuration
			$StigID = @("ESXI-06-000004","ESXI-06-100004","ESXI-06-200004","ESXI-06-300004","ESXI-06-400004","ESXI-06-500004")
			$loghost = $advopts | Where-Object { $_.Name -eq "Syslog.global.logHost" }
			$notes = "If the value in the current column is correct, this finding can be excluded in future checks."
			$results +=  Test-MultipleFindings -Category "II" -Setting "Remote Syslog Server Configuration" -Expected "Variable" -Current $loghost.Value -Impacted $notes -Remediation "Manual"

			# ESXI-06-000007 & ESXI-06-100007 - CAT II - Authorized Welcome Banner
			$StigID = @("ESXI-06-000007","ESXI-06-100007")
			$welcome = $advopts | Where-Object { $_.Name -eq "Annotations.WelcomeMessage" }
			$results +=  Test-MultipleFindings -Category "II" -Setting "Authorized Welcome Banner" -Expected "Variable" -Current $welcome.Value -Impacted $notes -Remediation "Manual"

			# ESXI-06-000008 - CAT II - Authorized Login Banner
			$issue = $advopts | Where-Object { $_.Name -eq "Config.Etc.issue" }
			$results += Test-Finding -Finding "ESXI-06-000008" -Category "II" -Setting "Authorized Login Banner" -Expected "Variable" -Current $issue.Value -Impacted $notes -Remediation "Manual"

			# ESXI-06-000062 - CAT II - dvFilter Network Host Configuration
			$bindIp = $advopts | Where-Object { $_.Name -eq "Net.DVFilterBindIpAddress" }
			if ($bindIp.value.length -eq 0 -or $bindIp.value -eq $null) {
				$check = $true 
				$notes = $null
			}
			
			else {
				$check = $bindIp.Value
				$expected = "Variable"
				$notes = "dvFilter has been configured on this host to send to: $($bindIp.Value)"
			}
			
			$results += Test-Finding -Finding "ESXI-06-000062" -Category "II" -Setting "dvFilter Network Host" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# Active Directory / Authentication
			$notes = $null
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for authentication configuration and users"
			$hostauth = Get-VMHostAuthentication -VMHost $entity
			$localUsers = $esxcli.system.account.list.Invoke().count
			if ($localUsers -le 3) { $extraUsers = $false }
			else { $extraUsers = $true }

			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for Host Profile Active Directory configuration"
			$hostProfile = Get-VMHostProfile -Entity $entity
			$hostProfileADConfig = $hostProfile.ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory
			if (($hostProfileADConfig.Policy | Where-Object { $_.Id -eq "JoinedDomainPolicy" }).Policyoption.Id -eq "FixedJoinedDomainOption") { $joinDomain = $true }
			else { $joinDomain = $false }

			if (($hostProfileADConfig.Policy | Where-Object { $_.Id -eq "JoinDomainMethod" }).Policyoption.Id -eq "FixedCAMConfigOption") { $joinMethod = $true }
			else { $joinMethod = $false }

			# ESXI-06-000038, ESXI-06-100038, ESXI-06-200038, ESXI-06-300038 - CAT II - vSphere Host Authentication Proxy
			if ($joinDomain -eq $false -and $extraUsers -eq $false) {
				$check = $true
				$notes = "No additional local users discovered and Active Directory is not configured in the host profile, so this finding is not applicable, per the STIG"
			}

			if ($extraUsers -eq $true -and $joinDomain -eq $false) {
				$check = $false
				$notes = "Per the STIG, this is a finding due to there being additional local user accounts on this host ($($localUsers.count) total users), but the host is not joined to the domain per it's host profile"
			}

			if ($joinDomain -eq $true) {
				if ($joinMethod -eq $true) { $check = $true }
				else { 
					$check = $false
					$notes = "Per the STIG, joining to Active Directory without using the vSphere Authentication Proxy is a finding"
				}
			}

			$StigID = @("ESXI-06-000038","ESXI-06-100038","ESXI-06-200038","ESXI-06-300038")
			$results +=  Test-MultipleFindings -Category "II" -Setting "vSphere Host Authentication Proxy" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# ESXI-06-000037, ESXI-06-100037, ESXI-06-200037, ESXI-06-300037 - CAT III - Joined to Active Directory Domain
			$notes = $null
			if ($hostauth.Domain -eq $null -and $extraUsers -eq $false) {
					$check = $true
					$notes = "No additional local users discovered and Active Directory is not configured for this host, so this finding is not applicable, per the STIG"
			}

			elseif ($hostauth.Domain -eq $null -and $extraUsers -eq $true) {
					$check = $false
					$notes = "Per the STIG, this is a finding due to there being additional local user accounts ($($localUsers.count) total users), but the host is not joined to an Active Directory Domain"
			}	

			else { $check = $true }
			
			$StigId = @("ESXI-06-000037","ESXI-06-100037","ESXI-06-200037","ESXI-06-300037")
			$results +=  Test-MultipleFindings -Category "III" -Setting "Active Directory Domain" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# EESXI-06-000039, ESXI-06-100039, ESXI-06-200039, & ESXI-06-300039 - CAT III - Non-Default ESX Admins Group
			$notes = $null
			$adminsGroup = $advopts | Where-Object { $_.Name -eq "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" }
			if ($hostauth.Domain -eq $null -and $extraUsers -eq $false) {
					$check = $true
					$notes = "No additional local users discovered and Active Directory is not configured for this host, so this finding is not applicable, per the STIG"
			}

			if ($hostauth.Domain -ne $null) {
				if ($adminsGroup.Value -ne "ESX Admins") { $check = $true }
				else {
					$check = $false
					$notes = "Change the value of 'Config.HostAgent.plugins.hostsvc.esxAdminsGroup' to whatever is appropriate for the environment/enclave"
				}
			}
			$StigID = @("ESXI-06-000039","ESXI-06-100039","ESXI-06-200039","ESXI-06-300039")
			$results +=  Test-MultipleFindings -Category "III" -Setting "Non-Default ESX Admins Group" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"

			# ESXI-06-000040, ESXI-06-100040, ESXI-06-200040, ESXI-06-300040 - CAT III - Smart Card Configuration
			$StigID = @("ESXI-06-000040", "ESXI-06-100040", "ESXI-06-200040", "ESXI-06-300040")
			$notes = $null
			if ($extraUsers -eq $false) {
				$check = $true
				$notes = "Per the STIG, this check is not applicable due to the system not having any additional local accounts beyond the defaults"
			}

			else {
				$smartcard = $entity.ExtensionData.Config.AuthenticationManagerInfo.AuthConfig[1].SmartCardAuthenticationEnabled
				if ($smartcard -eq $true) { $check = $true }
				else { 
					$check = $false
					$notes = "Smart Card authentication is not configured for this host"
				}
			}

			$results +=  Test-MultipleFindings -Category "III" -Setting "Smart Card Configuration" -Expected $true -Current $check -Impacted $notes -Remediation "Manual"			

			#Returning the results
			if ($Export) { $ExportResults += $results }
			else { $results }
		}
	}

	End { 
		if ($Export) { Export-Results }
	}
}