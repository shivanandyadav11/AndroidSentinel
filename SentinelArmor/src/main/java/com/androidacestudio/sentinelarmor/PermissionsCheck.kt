package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.PackageManager

/**
 * PermissionsCheck
 *
 * This class implements the [SecurityCheck] interface to perform an analysis of
 * the permissions requested by the Android application. It examines the app's
 * manifest to identify potentially risky or overly broad permissions that
 * might pose security concerns.
 *
 * Analyzing permissions is crucial for identifying potential security risks,
 * as overly broad or unnecessary permissions can increase the attack surface
 * of an application and potentially lead to data leaks or unauthorized access.
 *
 * Key features:
 * - Examines all permissions requested by the application
 * - Identifies specific high-risk permissions (e.g., INTERNET, WRITE_EXTERNAL_STORAGE)
 * - Provides security issues with varying severity levels based on the permissions used
 * - Offers recommendations for each identified permission-related security issue
 *
 * Note: This check focuses on manifest-declared permissions. It does not verify
 * runtime permission handling or the actual usage of permissions within the app's code.
 *
 * @property context The Android application context, used to access the app's package information.
 *
 * @see SecurityCheck
 * @see SecurityIssue
 */
internal class PermissionsCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the permissions check.
     *
     * This method implements the [SecurityCheck.check] function to analyze
     * the permissions requested by the application. It retrieves the app's
     * requested permissions from the package manager and evaluates each one
     * for potential security risks.
     *
     * The method currently checks for:
     * - INTERNET permission: Flagged as LOW severity, as it's common but should be used securely.
     * - WRITE_EXTERNAL_STORAGE permission: Flagged as MEDIUM severity due to potential data exposure risks.
     *
     * @return A list of [SecurityIssue] objects, each representing a potential
     *         security concern related to a specific permission. Returns an empty
     *         list if no permission-related issues are found.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageInfo =
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_PERMISSIONS,
            )

        packageInfo.requestedPermissions?.forEach { permission ->
            when {
                permission.contains("android.permission.INTERNET") ->
                    issues.add(
                        SecurityIssue(
                            severity = Severity.LOW,
                            description = "Internet permission granted",
                            recommendation = "Ensure proper network security measures are in place.",
                        ),
                    )

                permission.contains("android.permission.WRITE_EXTERNAL_STORAGE") ->
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "External storage write permission granted",
                            recommendation = "Be cautious about storing sensitive data.",
                        ),
                    )
            }
        }
        return issues
    }
}
