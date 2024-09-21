package com.androidacestudio.sentinelarmor

import android.content.Context

/**
 * AndroidSentinelImpl
 *
 * This class is the concrete implementation of the [AndroidSentinel] interface.
 * It orchestrates a comprehensive security analysis of an Android application by
 * executing a series of specific security checks.
 *
 * AndroidSentinelImpl aggregates multiple [SecurityCheck] implementations, each
 * focusing on a particular aspect of Android application security. When the
 * analysis is triggered, it runs all these checks and collates their results.
 *
 * Key features:
 * - Implements the [AndroidSentinel] interface
 * - Utilizes multiple specialized [SecurityCheck] implementations
 * - Provides a centralized point for executing all security checks
 * - Aggregates results from all checks into a single list of [SecurityIssue]s
 *
 * @property context The Android application context, used to access app-specific
 *                   information and resources required for various security checks.
 *
 * @constructor Creates an instance of AndroidSentinelImpl with the given Android context.
 *
 * @see AndroidSentinel
 * @see SecurityCheck
 * @see SecurityIssue
 */
internal class AndroidSentinelImpl(
    private val context: Context,
) : AndroidSentinel {
    /**
     * List of security checks to be performed.
     *
     * This property initializes and holds instances of various [SecurityCheck]
     * implementations. Each check focuses on a specific aspect of Android security.
     *
     * The checks include, but are not limited to:
     * - Permission analysis
     * - Root detection
     * - Data encryption verification
     * - ADB debugging check
     * - Backup settings analysis
     * - Screen lock protection verification
     * - Insecure data storage detection
     * - Cryptography weakness analysis
     * - Clipboard vulnerability check
     * - Broadcast receivers security analysis
     * - WebView security verification
     * - Content provider exposure check
     * - Network security configuration analysis
     * - Firebase security rules verification
     * - SQL injection vulnerability detection
     * - JavaScript security in WebViews
     * - Tapjacking vulnerability check
     * - Deep link validation
     *
     * Note: This list can be easily extended with additional security checks as needed.
     */
    private val checks: List<SecurityCheck> =
        listOf(
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
            DeepLinkValidationCheck(context),
        )

    /**
     * Performs a comprehensive security analysis of the Android application.
     *
     * This method executes all the security checks defined in the [checks] list
     * and aggregates their results. Each check contributes zero or more
     * [SecurityIssue]s to the final result.
     *
     * The analysis covers a wide range of security aspects, providing a thorough
     * evaluation of the application's security posture.
     *
     * @return A list of [SecurityIssue] objects, each representing a detected
     *         security flaw or potential vulnerability. The list will be empty
     *         if no security issues are detected.
     *
     * Note: The execution time of this method depends on the number and complexity
     * of the security checks. It's recommended to call this method from a
     * background thread to avoid blocking the main thread in Android applications.
     *
     * @see SecurityCheck
     * @see SecurityIssue
     */
    override fun analyzeSecurityFlaws(): List<SecurityIssue> = checks.flatMap { checkList -> checkList.check() }
}
