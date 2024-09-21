package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.ApplicationInfo

/**
 * BackupAllowedCheck
 *
 * This class implements the [SecurityCheck] interface to verify if the Android
 * application allows backups. While app backups can be useful for data preservation,
 * they can also pose security risks if sensitive data is not properly protected
 * during the backup process.
 *
 * The check examines the application's manifest to determine if the
 * `android:allowBackup` flag is set to true, which is the default behavior
 * if not explicitly set to false.
 *
 * Key features:
 * - Checks if app backups are allowed based on the manifest configuration
 * - Provides a medium-severity security issue if backups are allowed
 * - Offers a recommendation to ensure proper protection of sensitive data
 *
 * Note: Allowing backups is not inherently insecure, but it requires careful
 * consideration and implementation to ensure that sensitive data is adequately
 * protected during the backup and restore processes.
 *
 * @property context The Android application context, used to access application info.
 *
 * @see SecurityCheck
 * @see SecurityIssue
 * @see ApplicationInfo
 */
internal class BackupAllowedCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the backup allowed check.
     *
     * This method implements the [SecurityCheck.check] function to verify if
     * the application allows backups. It examines the application's flags to
     * determine if the FLAG_ALLOW_BACKUP is set.
     *
     * If backups are allowed, it returns a security issue with medium severity,
     * recommending that developers ensure proper protection of sensitive data
     * during backup processes.
     *
     * @return A list containing a single [SecurityIssue] if backups are allowed,
     *         or an empty list if backups are not allowed.
     */
    override fun check(): List<SecurityIssue> {
        val backupAllowed = context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0
        return if (backupAllowed) {
            listOf(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "App allows backups",
                    recommendation = "Ensure sensitive data is properly protected during backup processes.",
                ),
            )
        } else {
            emptyList()
        }
    }
}
