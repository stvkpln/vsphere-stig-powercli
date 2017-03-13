vSphere 6.0 STIG Check and Remediation Module
	- Version: 1.0
	- Last Update: 2016-DEC-27
	- Updated by: Steve Kaplan (steve@intolerable.net)

==== Get-vCenterStigValues ====
The following checks must be conducted manually (with rationale for why they are not included in this module):

1) The following are checks that can only be conducted by logging into the vCenter Server and checking manually: 
	-   Category I: VCWN-06-000027
	-  Category II: VCWN-06-000002, VCWN-06-000004, VCWN-06-000022, VCWN-06-000028, VCWN-06-000029, VCWN-06-000030
	- Category III: VCWN-06-000025

2) The following category II findings relate to vSphere Single Sign-On: VCWN-06-000001, VCWN-06-000003, VCWN-06-000010, VCWN-06-000039, VCWN-06-000040, VCWN-06-000041, VCWN-06-000042, VCWN-06-000043, VCWN-06-000045, VCWN-06-000046, VCWN-06-000047

3) Category II findings VCWN-06-000005 & VCWN-06-100005 can be checked via PowerCLI by executing 'Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | Format-Table -Auto', but because this check is so environmentally specific and requires review of documentation of permissions and role assignment, there is no consistent way to programmatically provide a compliant status.

4) The following category II findings can only be checked manually within the vCenter Server: VCWN-06-000026, VCWN-06-000034, VCWN-06-000035

5) The following category II findings relate to checks against the backing databases for vCenter and Update Manager: VCWN-06-000032, VCWN-06-000033

6) Category III finding VCWN-06-000031 relates to a check for Update Manager and the use of Update Manager Download Service (UMDS), but PowerCLI does not currently provide a way to check download settings for the Update Manager service.

7) The following category II checks are conducted external to the vCenter Server: VCWN-06-000009, VCWN-06-000020


==== Set-vCenterStigValues ====
All noted manual checks from the 'Get-vCenterStigValues' function are out of scope for automated remediation due to a lack of a mechanism to check, let alone remediate the findings. In addition, the following findings are not currently in scope for automated remediation in this version of the module:


- VCWN-06-000018: This is a check for whether distributed portgroups are configured to use the Native VLAN. Because this may be by design, the Get-vCenterStigValues function will return a list of impacted portgroups to reviewed and determined if this is by design or not

- VCWN-06-000019: This is a check for whether distributed portgroups are configured to be used with virtual guest tagging. Because this may be by design, the Get-vCenterStigValues function will return a list of impacted portgroups to reviewed and determined if this is by design or not


==== Get-VMHostStigValues ====
The following checks must be conducted manually (with rationale for why they are not included in this module):

1) The following are checks that can only be conducted from a shell (local or SSH) due to checking of files on the system itself
	-   Category I: ESXI-06-000011, ESXI-06-000015
	-  Category II: ESXI-06-000009, ESXI-06-000010, ESXI-06-000012, ESXI-06-000013, ESXI-06-000016, ESXI-06-000017, ESXI-06-000020, ESXI-06-000021, ESXI-06-000023, ESXI-06-000024, ESXI-06-000025, ESXI-06-000028, ESXI-06-000029, ESXI-06-000032, ESXI-06-000033, ESXI-06-100010
	- Category III: ESXI-06-000014, ESXI-06-000018, ESXI-06-000019, ESXI-06-000022, ESXI-06-000026, ESXI-06-000027
  
 
2) Network validation tasks that require review: Because environemnts vary and requirements are different (and because hosts running ESXi 5.x may be checked where this isn't applicable)
	-  Category II: ESXI-06-000048, ESXI-06-000049, ESXI-06-000050
	- Category III: ESXI-06-000051, ESXI-06-000052

3) Checks that are external to the actual ESXi Host:
	-   Category I: ESXI-06-000071
	-  Category II: ESXI-06-000065, ESXI-06-000066, ESXI-06-000068, ESXI-06-000070
	- Category III: ESXI-06-000067


==== Set-VMHostStigValues ====
All noted manual checks from the 'Get-VMHostStigValues' function are out of scope for automated remediation due to a lack of a mechanism to check, let alone remediate the findings. In addition, the following findings are not currently in scope for automated remediation in this version of the module:

- The following findings relate to configuring of that generally are very environment (and sometimes even cluster) specific. These findings should ideally be remediated utilizing a host profile to ensure proper policy enforcement of these values are stored and available for a more streamlined remediation via vCenter. Impacted findings:

	01) Correct syslog server: ESXI-06-000004, ESXI-06-100004, ESXI-06-200004, ESXI-06-300004, ESXI-06-400004, ESXI-06-500004
	02) Persistent log storage location: ESXI-06-000045
	03) NTP Configuration: ESXI-06-000046, ESXI-06-100046
	05) Smart Card Authentication: ESXI-06-000040, ESXI-06-100040, ESXI-06-200040, ESXI-06-300040
	06) Active Directory Configuration: ESXI-06-000038, ESXI-06-100038, ESXI-06-200038, ESXI-06-300038
	07) Joining to Active Directory: ESXI-06-000037, ESXI-06-100037, ESXI-06-200037, ESXI-06-300037
	08) Non-Default ESX Admin Active Directory Group: ESXI-06-000039, ESXI-06-100039, ESXI-06-200039, ESXI-06-300039
	09) Kernel Core Dumps: ESXI-06-000044
	10) DoD Banner (Annotations.WelcomeMessageCheck): ESXI-06-000007, ESXI-06-100007
	11) DoD Banner (Config.Etc.issue): ESXI-06-000008
	12) SNMP Confiugration: ESXI-06-000053
	13) Lockdwon Exception Users: ESXI-06-000003
	14) Unrestricted access to host services: ESXI-06-000056
	15) Native VLAN for Standard Portgroup: ESXI-06-000063
	16) Virtual Guest Tagging for Standard Portgroup: ESXI-06-000064
	17) IPv6 Enablement: ESXI-06-000069

- ESXI-06-000072: This finding relates to a host's patch compliance status. Because applying patches generally requires a host to be placed into maintenance, and may require an extended window to remediate all applicable hosts, this is not done as an automated action.

ESXI-06-000054: This is a check for whether bidirectional CHAP authentication is being used for iSCSI. Becuase remediation would require a connectivity outage with the impacted storage array(s) to correct, remediation must be done manually

==== Get-VMStigValues ====
The following checks must be conducted manually:

-  Category II: VMCH-06-000044; this is a process check relating to primary access & administration of a system. The check is calling for leveraging Remote Display Protocol (Windows) or SSH as the primary method of logging in and accessing a virtual machine.

- Category III: VMCH-06-000043; this is a process check relating to use of templates, rather than provisioning new VM's. Implementation of most of the other checks can be mitigated by building a template with the STIG checks integrated already.


==== Set-VMStigValues ====
All noted manual checks from the 'Get-VMStigValues' function are out of scope for automated remediation due to a lack of a mechanism to check, let alone remediate the findings. In addition, the following findings are not currently in scope for automated remediation in this version of the module:

- Category I: VMCH-06-000007 covers the use of independent non-persistent disks. Because this may be expected behavior for a virtual machine, and correcting the configure requires a power off operation to remediate, this finding will require manual remediation.

- Category II: The following findings relate to the use of unauthorized devices, each specific to a distinct type of device. Because removal of these devices generally requires a virtual machine to be powered off, and these devices may be required for some purpose, remediation for the following should be conducted manually on a per-system basis: VMCH-06-000028 (floppy drives), VMCH-06-000030 (parallel devices), VMCH-06-000031 (serial devices), VMCH-06-000032 (USB devices)