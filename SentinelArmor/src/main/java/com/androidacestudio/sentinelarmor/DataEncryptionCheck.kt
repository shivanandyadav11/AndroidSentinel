package com.androidacestudio.sentinelarmor

import android.app.KeyguardManager
import android.content.Context
import android.os.Build

/**
 * DataEncryptionCheck
 *
 * This class implements the [SecurityCheck] interface to verify if device encryption
 * is enabled on the Android device. Device encryption is a crucial security feature
 * that protects data stored on the device from unauthorized access.
 *
 * The check is performed only on devices running Android Marshmallow (API 23) or higher,
 * as the [KeyguardManager.isDeviceSecure] method was introduced in this version.
 *
 * Key features:
 * - Verifies if the device has a secure lock screen set up (PIN, pattern, or password)
 * - Works on Android Marshmallow (API 23) and above
 * - Provides a high-severity security issue if device encryption is not enabled
 *
 * Note: This check assumes that a secure lock screen implies device encryption is enabled,
 * which is generally true for modern Android devices. However, some older or heavily
 * customized devices might have secure lock screens without full device encryption.
 *
 * @property context The Android application context, used to access system services.
 *
 * @see SecurityCheck
 * @see SecurityIssue
 * @see KeyguardManager
 */
internal class DataEncryptionCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the data encryption check.
     *
     * This method implements the [SecurityCheck.check] function to verify if
     * device encryption is enabled. It uses the [KeyguardManager] to determine
     * if the device has a secure lock screen set up, which is a prerequisite
     * for device encryption on modern Android devices.
     *
     * The check is only performed on devices running Android Marshmallow (API 23)
     * or higher. For devices running earlier versions of Android, this check
     * will always return an empty list, as the necessary API is not available.
     *
     * @return A list containing a single [SecurityIssue] if device encryption
     *         is not enabled, or an empty list if encryption is enabled or
     *         the check cannot be performed (on devices below API 23).
     */
    override fun check(): List<SecurityIssue> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyguardManager =
                context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            if (!keyguardManager.isDeviceSecure) {
                return listOf(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Device encryption is not enabled",
                        recommendation = "Enable device encryption to protect sensitive data.",
                    ),
                )
            }
        }
        return emptyList()
    }
}
