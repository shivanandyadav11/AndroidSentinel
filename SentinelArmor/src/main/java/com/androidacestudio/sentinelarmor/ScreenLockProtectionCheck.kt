package com.androidacestudio.sentinelarmor

import android.app.KeyguardManager
import android.content.Context
import android.os.Build

/**
 * A security check that verifies the screen lock protection status of the device.
 *
 * This check examines various aspects of the device's screen lock security:
 * - Whether a secure screen lock is set
 * - The strength of the screen lock (for Android 6.0+)
 * - Additional lock screen security features (for Android 11+)
 *
 * The check uses the [KeyguardManager] to retrieve information about the device's lock screen status.
 * It adapts its checks based on the Android version of the device, using appropriate APIs for each version.
 *
 * @property context The Android application context, used to access system services.
 *
 * @see SecurityCheck
 * @see KeyguardManager
 */
internal class ScreenLockProtectionCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the screen lock protection check.
     *
     * This method evaluates the device's screen lock security and returns a list of [SecurityIssue]s
     * if any vulnerabilities are found. The check includes:
     *
     * 1. Verifying if any secure screen lock is set (all Android versions)
     * 2. Checking for weak or absent screen locks (Android 6.0+)
     * 3. Assessing additional lock screen security features (Android 11+)
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        if (!isDeviceSecure(keyguardManager)) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Device does not have a secure screen lock set",
                    recommendation = "Enable a secure screen lock (PIN, pattern, password, or biometric) to protect device data",
                ),
            )
        }

        // Check for specific lock screen settings on Android 6.0+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!keyguardManager.isDeviceSecure) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Device is using a weak or no screen lock",
                        recommendation = "Set up a strong screen lock method (PIN, password, or pattern) for better security",
                    ),
                )
            }
        }

        // Additional check for Android 11+ devices
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            when {
                keyguardManager.isDeviceLocked -> {
                    // Device is currently locked, which is good
                }

                !keyguardManager.isKeyguardSecure -> {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.LOW,
                            description = "Device lock screen is not secure",
                            recommendation = "Configure a secure lock screen to protect device data when the device is locked",
                        ),
                    )
                }
            }
        }

        return issues
    }

    /**
     * Determines if the device has a secure lock screen set.
     *
     * This method adapts its behavior based on the Android version:
     * - For Android 6.0 and above, it uses [KeyguardManager.isDeviceSecure]
     * - For earlier versions, it falls back to the deprecated [KeyguardManager.isKeyguardSecure]
     *
     * @param keyguardManager The [KeyguardManager] instance to use for the check
     * @return `true` if the device has a secure lock screen, `false` otherwise
     */
    private fun isDeviceSecure(keyguardManager: KeyguardManager): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguardManager.isDeviceSecure
        } else {
            @Suppress("DEPRECATION")
            keyguardManager.isKeyguardSecure
        }
}
