REG ADD 'HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security' /v 'markinternalasunsafe' /t REG_DWORD /d '0' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security' /v 'markinternalasunsafe' /t REG_DWORD /d '0' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security' /v 'blockcontentexecutionfrominternet' /t REG_DWORD /d '1' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security' /v 'vbawarnings' /t REG_DWORD /d '4' /f
REG ADD 'HKCU\Software\Microsoft\Office\16.0\Common\Security' /v 'MacroRuntimeScanScope' /t REG_DWORD /d '2' /f
REG ADD 'HKCU\Software\Policies\Microsoft\Office\16.0\Common\Security' /v 'MacroRuntimeScanScope' /t REG_DWORD /d '2' /f
REG ADD 'HKCU\Software\Microsoft\Office\14.0\Word\Options' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMai' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKCU\Software\Microsoft\Office\15.0\Word\Options' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMai' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKCU\Software\Microsoft\Office\16.0\Word\Options' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMai' /v 'DontUpdateLinks' /t REG_DWORD /d '00000001' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen' /f
REG ADD 'HKLM\Software\Adobe\Acrobat Reader\DC\Installer' /v 'DisableMaintenance' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bAcroSuppressUpsell' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bDisablePDFHandlerSwitching' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bDisableTrustedFolders' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bDisableTrustedSites' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bEnableFlash' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bEnhancedSecurityInBrowser' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bEnhancedSecurityStandalone' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'bProtectedMode' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'iFileAttachmentPerms' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' /v 'iProtectedView' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud' /v 'bAdobeSendPluginToggle' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms' /v 'iURLPerms' /t REG_DWORD /d '3' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms' /v 'iUnknownURLPerms' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /v 'bToggleAdobeDocumentServices' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /v 'bToggleAdobeSign' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /v 'bTogglePrefsSync' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /v 'bToggleWebConnectors' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' /v 'bUpdater' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint' /v 'bDisableSharePointFeatures' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles' /v 'bDisableWebmail' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen' /v 'bShowWelcomeScreen' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer' /v 'DisableMaintenance' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v 'SupportedEncryptionTypes' /t REG_DWORD /d '2147483640' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v 'EnableMulticast' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v 'DisableSmartNameResolution' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' /v 'DisableParallelAandAAAA' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' /v 'IGMPLevel' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' /v 'DisableIPSourceRouting' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' /v 'EnableICMPRedirect' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' /v 'DisableIPSourceRouting' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'SMB1' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' /v 'RestrictNullSessAccess' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableVirtualization' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v 'SaveZoneInformation' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoDataExecutionPrevention' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoHeapTerminationOnCorruption' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' /v 'DisableWebPnPDownload' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' /v 'DisableHTTPPrinting' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' /v 'AutoConnectAllowedOEM' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' /v 'fMinimizeConnections' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' /v 'NoNameReleaseOnDemand' /t REG_DWORD /d '1' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' /v 'RestrictReceivingNTLMTraffic' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' /v 'RestrictSendingNTLMTraffic' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v MinEncryptionLevel /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v SecurityLayer /t REG_DWORD /d 00000002 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0' /v allownullsessionfallback /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RestrictAnonymous /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RestrictRemoteSAM /t REG_SZ /d 'O:BAG:BAD:(A;;RC;;;BA)' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v UseMachineId /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' /v WpadOverride /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v FilterAdministratorToken /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' /v RestrictRemoteClients /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Internet Explorer\Main' /v DisableFirstRunCustomize /t REG_DWORD /d 2 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' /v 'RequireSecuritySignature' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' /v 'EnableSecuritySignature' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters' /v 'RequireSecuritySignature' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters' /v 'EnableSecuritySignature' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters' /v 'LDAPServerIntegrity' /t REG_DWORD /d 2 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\ldap' /v 'LDAPClientIntegrity ' /t REG_DWORD /d 2 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters' /v RequireSignOrSeal /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters' /v SealSecureChannel /t REG_DWORD /d 1 /f
REG ADD 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters' /v SignSecureChannel /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v EnableSmartScreen /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v ShellSmartScreenLevel /t REG_SZ /d Block /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' /v ProtectionMode /t REG_DWORD /d 1 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' /v ActiveDebugging /t REG_SZ /d 1 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' /v DisplayLogo /t REG_SZ /d 1 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' /v SilentTerminate /t REG_SZ /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' /v UseWINSAFER /t REG_SZ /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters' /v DisabledComponents /t REG_DWORD /d 0xFF /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' /v DODownloadMode /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\' /v DODownloadMode /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' /v ACSettingIndex /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' /v DCSettingIndex /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' /v fAllowToGetHelp /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' /v fDisableCdm /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoAutorun /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoRecentDocsHistory /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoRecentDocsMenu /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
REG ADD 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' /v DisableAutoplay /t REG_DWORD /d 1 /f
REG ADD 'HKEY_CLASSES_ROOT\Windows.IsoFile\shell\mount' /v ProgrammaticAccessOnly /t REG_SZ /f
REG ADD 'HKEY_CLASSES_ROOT\Windows.VhdFile\shell\mount' /v ProgrammaticAccessOnly /t REG_SZ /f
REG ADD 'HKCU\Control Panel\Accessibility\StickyKeys' /v 'Flags' /t REG_SZ /d '506' /f
REG ADD 'HKLU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v ShowFrequent /t REG_DWORD /d 0 /f
REG ADD 'HKLU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v ShowRecent /t REG_DWORD /d 0 /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'LaunchTo' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'HubMode' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' /v AllowDigest /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule' /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
REG ADD 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' /v Start /t REG_DWORD /d 4 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' /v AuditLevel /t REG_DWORD /d 00000008 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 00000001 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v Negotiate /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' /v AllowProtectedCreds /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' /v MyComputer /t REG_SZ /d 'Disabled' /f
REG ADD 'HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' /v LocalIntranet /t REG_SZ /d 'Disabled' /f
REG ADD 'HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' /v Internet /t REG_SZ /d 'Disabled' /f
REG ADD 'HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' /v TrustedSites /t REG_SZ /d 'Disabled' /f
REG ADD 'HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' /v UntrustedSites /t REG_SZ /d 'Disabled' /f
REG ADD 'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'HideFileExt' /t REG_DWORD /d 0 /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'HideFileExt' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Hidden' /t REG_DWORD /d 1 /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Hidden' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowSuperHidden' /t REG_DWORD /d 1 /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowSuperHidden' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'HiberbootEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' /v NoLockScreenCamera /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v Enabled /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' /v Enabled /t REG_DWORD /d 0xffffffff /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' /v DisabledByDefault /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v EnableOcspStaplingForSni /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' /v Functions /t REG_SZ /d 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256' /f
REG ADD 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Microsoft\Cryptography\Wintrust\Config' /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
REG ADD 'HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0' /v '1001' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1' /v '1001' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' /v '1001' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /v '1001' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0' /v '1004' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1' /v '1004' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' /v '1004' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /v '1004' /t REG_DWORD /d 00000003 /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge'  /v 'BackgroundModeEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' /v EnabledV9 /t REG_DWORD /d 1 /f
REG ADD 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' /v SafeForScripting /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' /v 'FormSuggest Passwords' /t REG_SZ /d no /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'SitePerProcess' /t REG_DWORD /d '0x00000001' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'SSLVersionMin' /t REG_SZ /d 'tls1.2^@' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'NativeMessagingUserLevelHosts' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'SmartScreenEnabled' /t REG_DWORD /d '0x00000001' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'PreventSmartScreenPromptOverride' /t REG_DWORD /d '0x00000001' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'PreventSmartScreenPromptOverrideForFiles' /t REG_DWORD /d '0x00000001' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'SSLErrorOverrideAllowed' /t REG_DWORD /d '0' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'SmartScreenPuaEnabled' /t REG_DWORD /d '0x00000001' /f
REG ADD 'HKLM\Software\Policies\Microsoft\Edge' /v 'AllowDeletingBrowserHistory' /t REG_DWORD /d '0x00000000' /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AdvancedProtectionAllowed' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AllowCrossOriginAuthPrompt' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AlwaysOpenPdfExternally' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AmbientAuthenticationInPrivateModesEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AudioCaptureAllowed' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AudioSandboxEnabled' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'BlockExternalExtensions' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'SSLVersionMin' /t REG_SZ /d tls1.1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'ScreenCaptureAllowed' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'SitePerProcess' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'TLS13HardeningForLocalAnchorsEnabled' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'VideoCaptureAllowed' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AllowFileSelectionDialogs' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AlwaysOpenPdfExternally' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AutoFillEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AutofillAddressEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AutofillCreditCardEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'PasswordManagerEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'MetricsReportingEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'ImportSavedPasswords' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'CloudPrintSubmitEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'CloudPrintProxyEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AllowOutdatedPlugins' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'AlternateErrorPagesEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'DnsOverHttpsMode' /t REG_SZ /d 'secure' /f
REG ADD 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'DnsOverHttpsTemplates' /t REG_SZ /d 'https://1.1.1.1/dns-query' /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'AllowOutdatedPlugins' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'AlternateErrorPagesEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'BlockThirdPartyCookies' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'ImportAutofillFormData' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'UrlKeyedAnonymizedDataCollectionEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'WebRtcEventLogCollectionAllowed' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'SafeBrowsingProtectionLevel' /t REG_DWORD /d '2' /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'BackgroundModeEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'PasswordLeakDetectionEnabled' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'RemoteDebuggingAllowed' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'UserFeedbackAllowed' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'DNSInterceptionChecksEnabled' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome' /v 'AlternateErrorPagesEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome\Recommended' /v 'RestoreOnStartup' /t REG_DWORD /d 1 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome\Recommended' /v 'TranslateEnabled' /t REG_DWORD /d 0 /f
REG ADD 'HKLM\Software\Policies\Google\Chrome\Recommended' /v 'DefaultDownloadDirectory' /t REG_SZ /d 'C:\Users\vibrio\Desktop' /f
REG ADD 'HKLM\Software\Policies\Google\Chrome\Recommended' /v 'DownloadDirectory' /t REG_SZ /d 'C:\Users\vibrio\Desktop' /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' /v EnableAutoDoh /t REG_DWORD /d 2 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' /v Location /t REG_SZ /d Deny /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v BingSearchEnabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v CortanaConsent /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v PublishUserActivities /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync' /v DisableSettingSync /t REG_DWORD /d 2 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR' /v AllowGameDVR /t REG_DWORD /d 0 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
REG ADD 'HKCU\Control Panel\International\User Profile' /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' /v EnableModuleLogging /t REG_DWORD /d 1 /f
REG ADD 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
REG ADD 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
REG ADD 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\Software\Microsoft\OLE' /v EnableDCOM /t REG_SZ /d N /F
reg add 'HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' /v DriverLoadPolicy /t REG_DWORD /d 3 /f
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v DisableCompression /t REG_DWORD /d 1 /f
reg DELETE 'HKEY_CLASSES_ROOT\ms-msdt' /f
reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f

Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage
Get-AppxPackage *ActiproSoftwareLLC* -AllUsers | Remove-AppxPackage
Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage
Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* -AllUsers | Remove-AppxPackage
Get-AppxPackage *BubbleWitch3Saga* -AllUsers | Remove-AppxPackage
Get-AppxPackage *CandyCrush* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Dolby* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Duolingo-LearnLanguagesforFree* -AllUsers | Remove-AppxPackage
Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Facebook* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Flipboard* -AllUsers | Remove-AppxPackage
Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.NetworkSpeedTest* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.News* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Lens* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Todo.List* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.RemoteDesktop* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.StorePurchaseApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Whiteboard* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage
Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxTCUI* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Minecraft* -AllUsers | Remove-AppxPackage
Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage
Get-AppxPackage *PandoraMediaInc* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Royal Revolt* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Speed Test* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Spotify* -AllUsers | Remove-AppxPackage
Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Sway* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Twitter* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Wunderlist* -AllUsers | Remove-AppxPackage
Get-AppxPackage Microsoft.549981C3F5F10 -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Office* -AllUsers | Remove-AppxPackage
Get-AppxPackage *ZuneVideo* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage
Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage

Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingNews'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Messaging'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Microsoft3DViewer'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.NetworkSpeedTest'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.News'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Lens'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Sway'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Todo.List'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.OneConnect'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Print3D'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.RemoteDesktop'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.StorePurchaseApp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Whiteboard'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Xbox.TCUI'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxSpeechToTextOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxTCUI'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*ActiproSoftwareLLC*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*AdobeSystemsIncorporated.AdobePhotoshopExpress*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*BubbleWitch3Saga*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*CandyCrush*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Dolby*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Duolingo-LearnLanguagesforFree*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*EclipseManager*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Facebook*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Flipboard*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.BingWeather**'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Minecraft*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*PandoraMediaInc*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Royal Revolt*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Speed Test*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Spotify*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Sway*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Twitter*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Wunderlist*'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Advertising.Xaml'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Xbox.TCUI'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxSpeechToTextOverlay'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Disney'} | Remove-AppxProvisionedPackage -Online

Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask
Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask
Get-ScheduledTask Consolidator | Disable-ScheduledTask
Get-ScheduledTask UsbCeip | Disable-ScheduledTask
Get-ScheduledTask DmClient | Disable-ScheduledTask
Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask

Set-WinLanguageBarOption -UseLegacyLanguageBar

Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl 'Windows Powershell' /ms:1024000
wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:1024000

$PhysAdapter = Get-NetAdapter -Physical;$PhysAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses '1.1.1.1','8.8.8.8'

fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
setx __PSLockdownPolicy '4' /M
powercfg -h off