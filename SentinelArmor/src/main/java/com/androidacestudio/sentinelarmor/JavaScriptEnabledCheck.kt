package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.PackageManager
import android.webkit.WebView
import dalvik.system.DexFile
import java.io.File

/**
 * A security check that examines the usage of JavaScript in WebViews within Android applications.
 *
 * This check analyzes various aspects of JavaScript usage in WebViews:
 * - Detection of WebView usage in the application
 * - Identification of JavaScript being enabled in WebViews
 * - Examination of JavaScript interfaces added to WebViews
 * - Checking for safe browsing and content security policy implementations
 * - Analyzing file access settings in WebViews
 *
 * The check aims to identify potential security vulnerabilities related to JavaScript
 * execution in WebViews.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see WebView
 */
internal class JavaScriptEnabledCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the JavaScript enabled check for WebViews.
     *
     * This method evaluates various aspects of JavaScript usage in WebViews,
     * returning a list of [SecurityIssue]s if any vulnerabilities or risky configurations are found.
     * The check includes:
     *
     * 1. Detecting WebView usage in the application
     * 2. Checking if JavaScript is enabled in WebViews
     * 3. Examining JavaScript interfaces added to WebViews
     * 4. Verifying safe browsing and content security policy implementations
     * 5. Analyzing file access settings in WebViews
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        if (isWebViewUsed()) {
            issues.addAll(checkJavaScriptEnabled())
            issues.addAll(checkJavaScriptInterfaces())
            issues.addAll(checkSafeBrowsing())
            issues.addAll(checkFileAccessSettings())
        }
        return issues
    }

    /**
     * Checks if WebView is used in the application.
     *
     * @return true if WebView is used, false otherwise.
     */
    private fun isWebViewUsed(): Boolean {
        val packageInfo =
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_ACTIVITIES,
            )
        return packageInfo.activities.any { it.name.contains("WebView", ignoreCase = true) }
    }

    /**
     * Checks if JavaScript is enabled in WebViews.
     *
     * @return A list of [SecurityIssue]s related to JavaScript being enabled.
     */
    private fun checkJavaScriptEnabled(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("setJavaScriptEnabled(true)")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "JavaScript is enabled in WebView in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Disable JavaScript if not necessary. If required, ensure proper security measures are in place.",
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
                    description = "Unable to analyze JavaScript enablement: ${e.message}",
                    recommendation = "Manually review WebView configurations for JavaScript usage.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks for JavaScript interfaces added to WebViews.
     *
     * @return A list of [SecurityIssue]s related to JavaScript interfaces.
     */
    private fun checkJavaScriptInterfaces(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("addJavascriptInterface(")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.MEDIUM,
                                    description = "JavaScript interface added to WebView in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Ensure the JavaScript interface is properly secured and only exposes necessary functionality.",
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
                    description = "Unable to analyze JavaScript interfaces: ${e.message}",
                    recommendation = "Manually review WebView configurations for JavaScript interface usage.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks for safe browsing implementation in WebViews.
     *
     * @return A list of [SecurityIssue]s related to safe browsing settings.
     */
    private fun checkSafeBrowsing(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            var safeBrowsingFound = false
            DexFile(apkFile).entries().toList().forEachIndexed { _, className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("setSafeBrowsingEnabled(true)")) {
                            safeBrowsingFound = true
                            return@forEachIndexed
                        }
                    }
                }
            }

            if (!safeBrowsingFound) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Safe Browsing is not explicitly enabled for WebViews",
                        recommendation = "Enable Safe Browsing in WebViews to protect against malicious websites.",
                    ),
                )
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze Safe Browsing settings: ${e.message}",
                    recommendation = "Manually review WebView configurations for Safe Browsing implementation.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks file access settings in WebViews.
     *
     * @return A list of [SecurityIssue]s related to file access settings.
     */
    private fun checkFileAccessSettings(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("setAllowFileAccess(true)")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "File access is allowed in WebView in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Disable file access in WebViews unless absolutely necessary. If required, implement strict constraints.",
                                ),
                            )
                        }
                        if (body.contains("setAllowFileAccessFromFileURLs(true)")) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "File access from file URLs is allowed in WebView in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Disable file access from file URLs to prevent potential security vulnerabilities.",
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
                    description = "Unable to analyze file access settings: ${e.message}",
                    recommendation = "Manually review WebView configurations for file access settings.",
                ),
            )
        }
        return issues
    }
}
