package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import dalvik.system.DexFile
import java.io.File

/**
 * A security check that examines the usage of Broadcast Receivers in Android applications
 * and identifies potential vulnerabilities associated with them.
 *
 * This check analyzes various aspects of Broadcast Receiver usage:
 * - Detection of exported Broadcast Receivers
 * - Examination of intent filter configurations
 * - Analysis of permission settings for Broadcast Receivers
 * - Identification of potential sensitive data handling in Broadcast Receivers
 * - Detection of potential security vulnerabilities in Broadcast Receiver implementations
 *
 * The check aims to identify potential vulnerabilities related to improper
 * Broadcast Receiver configuration and insufficient protection mechanisms.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 */
internal class BroadcastReceiversCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the Broadcast Receivers security check.
     *
     * This method evaluates various aspects of Broadcast Receiver usage in the application,
     * returning a list of [SecurityIssue]s if any potential vulnerabilities or misconfigurations are found.
     * The check includes:
     *
     * 1. Analyzing Broadcast Receiver declarations in the manifest
     * 2. Examining intent filter configurations
     * 3. Checking permission settings for Broadcast Receivers
     * 4. Identifying potential sensitive data handling in Broadcast Receivers
     * 5. Detecting potential security vulnerabilities in Broadcast Receiver implementations
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkBroadcastReceiverDeclarations())
        issues.addAll(checkIntentFilterConfigurations())
        issues.addAll(checkPermissionSettings())
        issues.addAll(checkSensitiveDataHandling())
        issues.addAll(checkImplementationVulnerabilities())
        return issues
    }

    /**
     * Analyzes Broadcast Receiver declarations in the manifest.
     *
     * @return A list of [SecurityIssue]s related to Broadcast Receiver declarations.
     */
    private fun checkBroadcastReceiverDeclarations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_RECEIVERS,
                )

            packageInfo.receivers?.forEach { receiverInfo ->
                if (receiverInfo.exported) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.HIGH,
                            description = "Exported Broadcast Receiver detected: ${receiverInfo.name}",
                            recommendation = "Ensure that exported Broadcast Receivers are necessary. If required, implement proper security measures such as permissions or intent filters.",
                        ),
                    )
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze Broadcast Receiver declarations: ${e.message}",
                    recommendation = "Manually review the AndroidManifest.xml for proper Broadcast Receiver declarations.",
                ),
            )
        }
        return issues
    }

    /**
     * Examines intent filter configurations for Broadcast Receivers.
     *
     * @return A list of [SecurityIssue]s related to intent filter configurations.
     */
    private fun checkIntentFilterConfigurations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_RECEIVERS,
                )

            packageInfo.receivers?.forEach { receiverInfo ->
                if (receiverInfo.exported) {
                    val pm = context.packageManager
                    val componentName =
                        android.content.ComponentName(context.packageName, receiverInfo.name)

                    // Query for receiver information including intent filters
                    val intent = Intent()
                    intent.setComponent(componentName)
                    val resolveInfo =
                        pm.queryBroadcastReceivers(intent, PackageManager.GET_RESOLVED_FILTER)

                    if (resolveInfo.isEmpty() || resolveInfo[0].filter == null || resolveInfo[0].filter.countActions() == 0) {
                        issues.add(
                            SecurityIssue(
                                severity = Severity.HIGH,
                                description = "Exported Broadcast Receiver ${receiverInfo.name} without specific intent filters",
                                recommendation = "Add specific intent filters to restrict the types of intents the receiver can handle.",
                            ),
                        )
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
     * Checks permission settings for Broadcast Receivers.
     *
     * @return A list of [SecurityIssue]s related to permission settings.
     */
    private fun checkPermissionSettings(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_RECEIVERS or PackageManager.GET_PERMISSIONS,
                )

            packageInfo.receivers?.forEach { receiverInfo ->
                if (receiverInfo.exported && receiverInfo.permission == null) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "Exported Broadcast Receiver ${receiverInfo.name} without permission protection",
                            recommendation = "Add a custom permission to protect the Broadcast Receiver from unauthorized access.",
                        ),
                    )
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze permission settings: ${e.message}",
                    recommendation = "Manually review the AndroidManifest.xml for proper permission settings on Broadcast Receivers.",
                ),
            )
        }
        return issues
    }

    /**
     * Identifies potential sensitive data handling in Broadcast Receivers.
     *
     * @return A list of [SecurityIssue]s related to sensitive data handling.
     */
    private fun checkSensitiveDataHandling(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    if (android.content.BroadcastReceiver::class.java.isAssignableFrom(clazz)) {
                        clazz.declaredMethods.forEach { method ->
                            val body = method.toGenericString()
                            if (body.contains("onReceive(") &&
                                (
                                    body.contains("getStringExtra(") ||
                                        body.contains(
                                            "getBooleanExtra(",
                                        )
                                )
                            ) {
                                issues.add(
                                    SecurityIssue(
                                        severity = Severity.MEDIUM,
                                        description = "Potential sensitive data handling in Broadcast Receiver: ${clazz.simpleName}.${method.name}",
                                        recommendation = "Ensure that sensitive data is not transmitted via Broadcast Intents. If necessary, implement proper encryption and validation.",
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
                    description = "Unable to analyze sensitive data handling in Broadcast Receivers: ${e.message}",
                    recommendation = "Manually review Broadcast Receiver implementations for proper handling of sensitive data.",
                ),
            )
        }
        return issues
    }

    /**
     * Detects potential security vulnerabilities in Broadcast Receiver implementations.
     *
     * @return A list of [SecurityIssue]s related to implementation vulnerabilities.
     */
    private fun checkImplementationVulnerabilities(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    if (android.content.BroadcastReceiver::class.java.isAssignableFrom(clazz)) {
                        clazz.declaredMethods.forEach { method ->
                            val body = method.toGenericString()
                            if (body.contains("onReceive(")) {
                                if (!body.contains("getAction()") || !body.contains("if (")) {
                                    issues.add(
                                        SecurityIssue(
                                            severity = Severity.HIGH,
                                            description = "Potential lack of intent action validation in Broadcast Receiver: ${clazz.simpleName}.${method.name}",
                                            recommendation = "Always validate the intent action in onReceive() before processing the intent.",
                                        ),
                                    )
                                }
                                if (body.contains("startService(") || body.contains("bindService(")) {
                                    issues.add(
                                        SecurityIssue(
                                            severity = Severity.MEDIUM,
                                            description = "Service invocation detected in Broadcast Receiver: ${clazz.simpleName}.${method.name}",
                                            recommendation = "Be cautious when starting services from Broadcast Receivers. Ensure proper validation and consider using JobIntentService for background work.",
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
                    description = "Unable to analyze Broadcast Receiver implementations: ${e.message}",
                    recommendation = "Manually review Broadcast Receiver implementations for potential security vulnerabilities.",
                ),
            )
        }
        return issues
    }
}
