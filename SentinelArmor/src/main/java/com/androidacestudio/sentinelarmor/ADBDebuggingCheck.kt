package com.androidacestudio.sentinelarmor

import android.content.Context
import android.provider.Settings

internal class ADBDebuggingCheck(private val context: Context) : SecurityCheck {
    override fun check(): List<SecurityIssue> {
        val adbEnabled =
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        return if (adbEnabled) {
            listOf(
                SecurityIssue(
                    Severity.MEDIUM,
                    "ADB debugging is enabled",
                    "Disable ADB debugging in production builds to prevent unauthorized access."
                )
            )
        } else {
            emptyList()
        }
    }
}