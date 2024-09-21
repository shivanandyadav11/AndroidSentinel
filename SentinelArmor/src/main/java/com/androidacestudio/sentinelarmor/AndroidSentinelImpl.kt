package com.androidacestudio.sentinelarmor

import android.content.Context

internal class AndroidSentinelImpl(private val context: Context) : AndroidSentinel {
    private val checks: List<SecurityCheck> = listOf(
        PermissionsCheck(context),
        RootDetectionCheck(),
        DataEncryptionCheck(context),
        ADBDebuggingCheck(context),
        BackupAllowedCheck(context),
        ScreenLockProtectionCheck(context),
        InsecureDataStorageCheck(context),
        WeakCryptographyCheck(context),
        ClipboardVulnerabilityCheck(context),
        BroadcastReceiversCheck(context),
        WebViewSecurityCheck(context),
        ContentProviderExposureCheck(context),
        NetworkSecurityConfigCheck(context),
        FirebaseSecurityRulesCheck(context),
        SQLInjectionVulnerabilityCheck(context),
        JavaScriptEnabledCheck(context),
        TapjackingCheck(context),
        DeepLinkValidationCheck(context)
    )

    override fun analyzeSecurityFlaws(): List<SecurityIssue> {
        return checks.flatMap { checkList -> checkList.check() }
    }
}