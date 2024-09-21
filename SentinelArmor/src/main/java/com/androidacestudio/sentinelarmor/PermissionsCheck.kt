package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.PackageManager

internal class PermissionsCheck(private val context: Context) : SecurityCheck {
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageInfo = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS
        )

        packageInfo.requestedPermissions?.forEach { permission ->
            when {
                permission.contains("android.permission.INTERNET") ->
                    issues.add(
                        SecurityIssue(
                            Severity.LOW,
                            "Internet permission granted",
                            "Ensure proper network security measures are in place."
                        )
                    )

                permission.contains("android.permission.WRITE_EXTERNAL_STORAGE") ->
                    issues.add(
                        SecurityIssue(
                            Severity.MEDIUM,
                            "External storage write permission granted",
                            "Be cautious about storing sensitive data."
                        )
                    )
                // Add more permission checks here
            }
        }
        return issues
    }
}