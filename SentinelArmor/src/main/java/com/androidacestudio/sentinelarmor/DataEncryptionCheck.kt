package com.androidacestudio.sentinelarmor

import android.app.KeyguardManager
import android.content.Context
import android.os.Build

internal class DataEncryptionCheck(
    private val context: Context,
) : SecurityCheck {
    override fun check(): List<SecurityIssue> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyguardManager =
                context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            if (!keyguardManager.isDeviceSecure) {
                return listOf(
                    SecurityIssue(
                        Severity.HIGH,
                        "Device encryption is not enabled",
                        "Enable device encryption to protect sensitive data.",
                    ),
                )
            }
        }
        return emptyList()
    }
}
