package com.androidacestudio.sentinelarmor

import android.os.Build
import java.io.File

/**
 * RootDetectionCheck
 *
 * This class implements the [SecurityCheck] interface to perform root detection
 * on Android devices. It checks for common indicators of a rooted device, such as
 * the presence of specific files typically associated with root access and
 * the presence of test-keys in the device's build tags.
 *
 * Root detection is crucial for identifying potentially compromised devices,
 * as rooted devices can bypass certain security measures and potentially
 * expose the application to additional security risks.
 *
 * Key features:
 * - Checks for the existence of common root-related files
 * - Examines the device's build tags for indicators of root access
 * - Provides a high-severity security issue if root indicators are found
 *
 * Note: While this check can detect many common rooting methods, it's not
 * foolproof. Advanced rooting techniques may evade detection. Additionally,
 * some legitimate custom ROMs might trigger false positives.
 *
 * @see SecurityCheck
 * @see SecurityIssue
 */
internal class RootDetectionCheck : SecurityCheck {
    /**
     * Performs the root detection check.
     *
     * This method implements the [SecurityCheck.check] function to detect
     * signs of root access on the device. It performs two main checks:
     * 1. Searches for the existence of files commonly associated with root access.
     * 2. Checks if the device's build tags contain "test-keys", which often
     *    indicates a non-official, potentially rooted ROM.
     *
     * @return A list containing a single [SecurityIssue] if root indicators
     *         are found, or an empty list if no root indicators are detected.
     */
    override fun check(): List<SecurityIssue> {
        val rootFiles =
            arrayOf(
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
            )

        val isRooted =
            rootFiles.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true

        return if (isRooted) {
            listOf(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Device appears to be rooted",
                    recommendation = "Implement additional security measures for rooted devices.",
                ),
            )
        } else {
            emptyList()
        }
    }
}
