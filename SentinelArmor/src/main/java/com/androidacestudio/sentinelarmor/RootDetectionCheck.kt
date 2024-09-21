package com.androidacestudio.sentinelarmor

import java.io.File
import android.os.Build

internal class RootDetectionCheck : SecurityCheck {
    override fun check(): List<SecurityIssue> {
        val rootFiles = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )

        val isRooted =
            rootFiles.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true

        return if (isRooted) {
            listOf(
                SecurityIssue(
                    Severity.HIGH,
                    "Device appears to be rooted",
                    "Implement additional security measures for rooted devices."
                )
            )
        } else {
            emptyList()
        }
    }
}