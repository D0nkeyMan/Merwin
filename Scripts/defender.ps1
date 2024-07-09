# Delete Existing Exclusions
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' /v 'ExploitGuard_ASR_ASROnlyExclusions' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' /v 'ExploitGuard_ControlledFolderAccess_AllowedApplications' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Extensions' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Paths' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Processes' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'RealtimeScanDirection' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /f
REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Threats' /v 'Threats_ThreatSeverityDefaultAction' /f

# Ransomeware Protection
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' /v 'EnableControlledFolderAccess' /t 'REG_DWORD' /d '1' /f

REG DELETE 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications' /f

# Removable Device Protection
REG ADD 'HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions' /v 'DenyRemovableDevices' /t 'REG_DWORD' /d '1' /f

# Network Protection
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\AllowNetworkProtectionOnWinServer' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f

# Set Defender Settings
Set-MpPreference -AllowDatagramProcessingOnWinServer $true
Set-MpPreference -AllowNetworkProtectionDownLevel $true
Set-MpPreference -AllowNetworkProtectionOnWinServer $true
Set-MpPreference -AllowSwitchToAsyncInspection $true
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
Set-MpPreference -CloudBlockLevel "zeroTolerance"
Set-MpPreference -CloudExtendedTimeout 50
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableAutoExclusions $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableCacheMaintenance $false
Set-MpPreference -DisableCatchupFullScan $false
Set-MpPreference -DisableCatchupQuickScan $false
Set-MpPreference -DisableCpuThrottleOnIdleScans $true
Set-MpPreference -DisableDatagramProcessing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableFtpParsing $false
Set-MpPreference -DisableGradualRelease $false
Set-MpPreference -DisableHttpParsing $false
Set-MpPreference -DisableInboundConnectionFiltering $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -DisableRdpParsing $false
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -DisableRestorePoint $false
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
Set-MpPreference -DisableScanningNetworkFiles $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableSmtpParsing $false
Set-MpPreference -DisableSshParsing $false
Set-MpPreference -DisableTlsParsing $false
Set-MpPreference -EnableControlledFolderAccess "Enabled"
Set-MpPreference -EnableDnsSinkhole $true
Set-MpPreference -EnableFileHashComputation $true
Set-MpPreference -EnableFullScanOnBatteryPower $true
Set-MpPreference -EnableLowCpuPriority $false
Set-MpPreference -EnableNetworkProtection "Enabled"
Set-MpPreference -EngineUpdatesChannel "NotConfigured"
Set-MpPreference -HighThreatDefaultAction "Remove"
Set-MpPreference -IntelTDTEnabled 1
Set-MpPreference -LowThreatDefaultAction "Remove"
Set-MpPreference -MAPSReporting 0
Set-MpPreference -MeteredConnectionUpdates $true
Set-MpPreference -ModerateThreatDefaultAction "Remove"
Set-MpPreference -OobeEnableRtpAndSigUpdate $true
Set-MpPreference -PlatformUpdatesChannel "NotConfigured"
Set-MpPreference -PUAProtection "Enabled"
Set-MpPreference -QuarantinePurgeItemsAfterDelay 1
Set-MpPreference -RandomizeScheduleTaskTimes $true
Set-MpPreference -RealTimeScanDirection "Both"
Set-MpPreference -RemediationScheduleDay "Everyday"
Set-MpPreference -ScanOnlyIfIdleEnabled $false
Set-MpPreference -ScanParameters "FullScan"
Set-MpPreference -ScanScheduleDay "Everyday"
Set-MpPreference -SchedulerRandomizationTime $true
Set-MpPreference -ServiceHealthReportInterval 60
Set-MpPreference -SevereThreatDefaultAction "Remove"
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
Set-MpPreference -SignatureScheduleDay "Everyday"
Set-MpPreference -SignaturesUpdatesChannel "Everyday"
Set-MpPreference -SignatureUpdateCatchupInterval 0
Set-MpPreference -SubmitSamplesConsent "NeverSend"
Set-MpPreference -UILockdown $true
Set-MpPreference -UnknownThreatDefaultAction "Remove"

REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'PUAProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'DisableAntiSpyware' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'ASSignatureDue' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'AVSignatureDue' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableRealtimeMonitoring' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableBehaviorMonitoring' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableIOAVProtection' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'DisableScanOnRealtimeEnable' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideRealtimeScanDirection' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableOnAccessProtection' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\NIS' /v 'DisableProtocolRecognition' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'DisableAutoExclusions' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'DisableRealtimeMonitoring' /t 'REG_DWORD' /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'DisableRoutinelyTakingAction' /t 'REG_DWORD' /d '0' /f

# Remove Defender Exclusions
Remove-MpPreference -AttackSurfaceReductionRules_Ids * -AttackSurfaceReductionRules_Actions * -AttackSurfaceReductionOnlyExclusions *
Remove-MpPreference -ExclusionPath *
Remove-MpPreference -ExclusionExtension *
Remove-MpPreference -ExclusionProcess *
Remove-MpPreference -ExclusionIpAddress *
Remove-MpPreference -ThreatIDDefaultAction_Ids * -ThreatIDDefaultAction_Actions *
Remove-MpPreference -ControlledFolderAccessAllowedApplications * -ControlledFolderAccessProtectedFolders *

# Add ASR Rules (TODO: Add registry)
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions 1

REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' /v 'ExploitGuard_ASR_Rules' /t 'REG_DWORD' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '56a863a9-875e-4185-98a7-b882c64b5ce5' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '01443614-cd74-433a-b99e-2ecdc07bfc25' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '5beb7efe-fd9a-4556-801d-275e5ffc04cc' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd3e037e1-3eb8-44c8-a917-57927947596d' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '3b576869-a4ec-4529-8536-b80a7769e899' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '26190899-1602-49e8-8b27-eb1d0a1ce869' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'e6db77e5-3df2-4cf1-b95a-636979351e5b' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd1e49aac-8f56-4280-b9ba-993a6d77406c' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'a8f5898e-1dc8-49a9-9878-85004b8a61e6' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' /t 'REG_SZ' /d '1' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'c1db55ab-c21a-4637-bb3f-a12568109d35' /t 'REG_SZ' /d '1' /f

# Set Environment Variables
setx /M MP_FORCE_USE_SANDBOX 1

# Set Process Mitigations (TODO: Apply configuration from https://github.com/jdgregson/Exploit-Protection-Settings/blob/master/ExploitProtectionSettings.xml)

# Update Defender Signatures
Update-MpSignature