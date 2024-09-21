package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import dalvik.system.DexFile
import java.io.File

/**
 * A security check that examines the usage and validation of deep links in Android applications.
 *
 * This check analyzes various aspects of deep link handling:
 * - Detection of deep link declarations in the manifest
 * - Examination of intent filter configurations
 * - Analysis of deep link handling code
 * - Identification of potential validation issues
 * - Detection of sensitive data exposure through deep links
 *
 * The check aims to identify potential vulnerabilities related to improper
 * deep link handling and insufficient validation.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see Intent
 * @see Uri
 */
internal class DeepLinkValidationCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the deep link validation check.
     *
     * This method evaluates various aspects of deep link usage in the application,
     * returning a list of [SecurityIssue]s if any potential vulnerabilities or misconfigurations are found.
     * The check includes:
     *
     * 1. Analyzing deep link declarations in the manifest
     * 2. Examining intent filter configurations
     * 3. Checking deep link handling code for proper validation
     * 4. Identifying potential sensitive data exposure through deep links
     * 5. Detecting any use of dynamic deep link generation
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkDeepLinkDeclarations())
        issues.addAll(checkIntentFilterConfigurations())
        issues.addAll(checkDeepLinkHandlingCode())
        issues.addAll(checkSensitiveDataExposure())
        issues.addAll(checkDynamicDeepLinkGeneration())
        return issues
    }

    /**
     * Analyzes deep link declarations in the manifest.
     *
     * @return A list of [SecurityIssue]s related to deep link declarations.
     */
    private fun checkDeepLinkDeclarations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_ACTIVITIES or PackageManager.GET_META_DATA,
                )

            packageInfo.activities.forEach { activityInfo ->
                activityInfo.metaData?.let { metaData ->
                    if (metaData.containsKey("android.intent.action.VIEW")) {
                        val scheme = metaData.getString("android.intent.extra.SCHEME")
                        if (scheme == "http" || scheme == "https") {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.MEDIUM,
                                    description = "Unsecure deep link scheme (http/https) detected for ${activityInfo.name}",
                                    recommendation = "Consider using a custom URL scheme or App Links for more secure deep linking.",
                                ),
                            )
                        }
                    }
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze deep link declarations: ${e.message}",
                    recommendation = "Manually review the AndroidManifest.xml for proper deep link declarations.",
                ),
            )
        }
        return issues
    }

    /**
     * Examines intent filter configurations for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to intent filter configurations.
     */
    private fun checkIntentFilterConfigurations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_ACTIVITIES or PackageManager.GET_META_DATA,
                )

            packageInfo.activities.forEach { activityInfo ->
                activityInfo.metaData?.let { metaData ->
                    if (metaData.containsKey("android.intent.action.VIEW")) {
                        if (!metaData.containsKey("android.intent.category.BROWSABLE")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.MEDIUM,
                                    description = "Deep link intent filter for ${activityInfo.name} is missing BROWSABLE category",
                                    recommendation = "Add the BROWSABLE category to ensure the deep link can be invoked from web browsers.",
                                ),
                            )
                        }
                        if (!metaData.containsKey("android.intent.category.DEFAULT")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.LOW,
                                    description = "Deep link intent filter for ${activityInfo.name} is missing DEFAULT category",
                                    recommendation = "Add the DEFAULT category to ensure the deep link can be invoked implicitly.",
                                ),
                            )
                        }
                    }
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze intent filter configurations: ${e.message}",
                    recommendation = "Manually review the AndroidManifest.xml for proper intent filter configurations.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks deep link handling code for proper validation.
     *
     * @return A list of [SecurityIssue]s related to deep link handling code.
     */
    private fun checkDeepLinkHandlingCode(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("getIntent()") && body.contains("getData()")) {
                            if (!body.contains("validateDeepLink") && !body.contains("verifyDeepLink")) {
                                issues.add(
                                    SecurityIssue(
                                        severity = Severity.HIGH,
                                        description = "Potential lack of deep link validation in ${clazz.simpleName}.${method.name}",
                                        recommendation = "Implement proper deep link validation to prevent potential security vulnerabilities.",
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze deep link handling code: ${e.message}",
                    recommendation = "Manually review deep link handling code for proper validation.",
                ),
            )
        }
        return issues
    }

    /**
     * Identifies potential sensitive data exposure through deep links.
     *
     * @return A list of [SecurityIssue]s related to sensitive data exposure.
     */
    private fun checkSensitiveDataExposure(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("getIntent()") && body.contains("getData()")) {
                            if (body.contains("password") ||
                                body.contains("token") ||
                                body.contains(
                                    "secret",
                                )
                            ) {
                                issues.add(
                                    SecurityIssue(
                                        severity = Severity.HIGH,
                                        description = "Potential sensitive data exposure through deep links in ${clazz.simpleName}.${method.name}",
                                        recommendation = "Avoid passing sensitive data through deep links. Use secure alternatives for data transfer.",
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze for sensitive data exposure: ${e.message}",
                    recommendation = "Manually review deep link handling code for potential sensitive data exposure.",
                ),
            )
        }
        return issues
    }

    /**
     * Detects any use of dynamic deep link generation, which can be risky if not properly secured.
     *
     * @return A list of [SecurityIssue]s related to dynamic deep link generation.
     */
    private fun checkDynamicDeepLinkGeneration(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("Uri.parse(") && body.contains("Intent(Intent.ACTION_VIEW")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.MEDIUM,
                                    description = "Dynamic deep link generation detected in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Ensure dynamically generated deep links are properly validated and sanitized.",
                                ),
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze dynamic deep link generation: ${e.message}",
                    recommendation = "Manually review code for any dynamic deep link generation and ensure proper security measures.",
                ),
            )
        }
        return issues
    }
}
