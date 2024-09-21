package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import dalvik.system.DexFile
import java.io.File

/**
 * A security check that examines the usage and potential exposure of Content Providers
 * in Android applications.
 *
 * This check analyzes various aspects of Content Provider implementation:
 * - Detection of Content Provider declarations in the manifest
 * - Examination of Content Provider export settings
 * - Analysis of permissions associated with Content Providers
 * - Identification of potential data exposure through Content Providers
 * - Detection of SQL injection vulnerabilities in Content Provider implementations
 *
 * The check aims to identify potential vulnerabilities related to improper
 * Content Provider configuration and insufficient data protection.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see ProviderInfo
 */
internal class ContentProviderExposureCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the Content Provider exposure check.
     *
     * This method evaluates various aspects of Content Provider usage in the application,
     * returning a list of [SecurityIssue]s if any potential vulnerabilities or misconfigurations are found.
     * The check includes:
     *
     * 1. Analyzing Content Provider declarations in the manifest
     * 2. Examining Content Provider export settings
     * 3. Checking permissions associated with Content Providers
     * 4. Identifying potential data exposure through Content Providers
     * 5. Detecting potential SQL injection vulnerabilities in Content Provider implementations
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkContentProviderDeclarations())
        issues.addAll(checkContentProviderPermissions())
        issues.addAll(checkDataExposure())
        issues.addAll(checkSQLInjectionVulnerabilities())
        return issues
    }

    /**
     * Analyzes Content Provider declarations in the manifest.
     *
     * @return A list of [SecurityIssue]s related to Content Provider declarations.
     */
    private fun checkContentProviderDeclarations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_PROVIDERS,
                )

            packageInfo.providers?.forEach { providerInfo ->
                if (providerInfo.exported) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.HIGH,
                            description = "Exported Content Provider detected: ${providerInfo.name}",
                            recommendation = "Ensure that exported Content Providers are properly protected with permissions or signature-level protection.",
                        ),
                    )
                }
                if (providerInfo.readPermission == null && providerInfo.writePermission == null) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "Content Provider without read/write permissions: ${providerInfo.name}",
                            recommendation = "Add appropriate read and write permissions to protect the Content Provider's data.",
                        ),
                    )
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze Content Provider declarations: ${e.message}",
                    recommendation = "Manually review the AndroidManifest.xml for proper Content Provider declarations.",
                ),
            )
        }
        return issues
    }

    /**
     * Examines permissions associated with Content Providers.
     *
     * @return A list of [SecurityIssue]s related to Content Provider permissions.
     */
    private fun checkContentProviderPermissions(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS,
                )

            packageInfo.providers?.forEach { providerInfo ->
                if (providerInfo.exported) {
                    val readPermission = providerInfo.readPermission
                    val writePermission = providerInfo.writePermission

                    if (readPermission != null && !isCustomPermission(readPermission)) {
                        issues.add(
                            SecurityIssue(
                                severity = Severity.MEDIUM,
                                description = "Content Provider ${providerInfo.name} uses system-defined read permission: $readPermission",
                                recommendation = "Consider using a custom, app-specific permission for better security.",
                            ),
                        )
                    }

                    if (writePermission != null && !isCustomPermission(writePermission)) {
                        issues.add(
                            SecurityIssue(
                                severity = Severity.MEDIUM,
                                description = "Content Provider ${providerInfo.name} uses system-defined write permission: $writePermission",
                                recommendation = "Consider using a custom, app-specific permission for better security.",
                            ),
                        )
                    }
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze Content Provider permissions: ${e.message}",
                    recommendation = "Manually review Content Provider permissions in the AndroidManifest.xml.",
                ),
            )
        }
        return issues
    }

    /**
     * Identifies potential data exposure through Content Providers.
     *
     * @return A list of [SecurityIssue]s related to data exposure.
     */
    private fun checkDataExposure(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    if (android.content.ContentProvider::class.java.isAssignableFrom(clazz)) {
                        clazz.declaredMethods.forEach { method ->
                            val body = method.toGenericString()
                            if (body.contains("query(") ||
                                body.contains("insert(") ||
                                body.contains("update(") ||
                                body.contains("delete(")
                            ) {
                                if (!body.contains("checkCallingPermission(")) {
                                    issues.add(
                                        SecurityIssue(
                                            severity = Severity.HIGH,
                                            description = "Potential unprotected data access in Content Provider: ${clazz.simpleName}.${method.name}",
                                            recommendation = "Implement proper permission checks in Content Provider methods to protect data access.",
                                        ),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze Content Provider implementations: ${e.message}",
                    recommendation = "Manually review Content Provider implementations for proper data protection.",
                ),
            )
        }
        return issues
    }

    /**
     * Detects potential SQL injection vulnerabilities in Content Provider implementations.
     *
     * @return A list of [SecurityIssue]s related to SQL injection vulnerabilities.
     */
    private fun checkSQLInjectionVulnerabilities(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    if (android.content.ContentProvider::class.java.isAssignableFrom(clazz)) {
                        clazz.declaredMethods.forEach { method ->
                            val body = method.toGenericString()
                            if (body.contains("query(") ||
                                body.contains("update(") ||
                                body.contains(
                                    "delete(",
                                )
                            ) {
                                if (body.contains("rawQuery(") || body.contains("execSQL(")) {
                                    issues.add(
                                        SecurityIssue(
                                            severity = Severity.HIGH,
                                            description = "Potential SQL injection vulnerability in Content Provider: ${clazz.simpleName}.${method.name}",
                                            recommendation = "Use parameterized queries or prepared statements instead of raw SQL to prevent SQL injection.",
                                        ),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze for SQL injection vulnerabilities: ${e.message}",
                    recommendation = "Manually review Content Provider implementations for potential SQL injection vulnerabilities.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks if a given permission is a custom app-specific permission.
     *
     * @param permission The permission string to check.
     * @return true if it's a custom permission, false otherwise.
     */
    private fun isCustomPermission(permission: String): Boolean = permission.startsWith(context.packageName)
}
