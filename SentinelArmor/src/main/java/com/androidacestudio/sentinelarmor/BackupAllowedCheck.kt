package com.androidacestudio.sentinelarmor

import android.content.Context

internal class BackupAllowedCheck(
    private val context: Context,
) : SecurityCheck {
    override fun check(): List<SecurityIssue> {
        val backupAllowed =
            context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP != 0
        return if (backupAllowed) {
            listOf(
                SecurityIssue(
                    Severity.MEDIUM,
                    "App allows backups",
                    "Ensure sensitive data is properly protected during backup processes.",
                ),
            )
        } else {
            emptyList()
        }
    }
}
