package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.PackageManager
import android.webkit.WebSettings
import android.webkit.WebView

/**
 * A security check that identifies potential vulnerabilities in WebView configurations within Android applications.
 *
 * This check examines various aspects of WebView usage:
 * - JavaScript enablement
 * - File access from file URLs
 * - Content access from file URLs
 * - Universal access from file URLs
 * - Mixed content handling
 * - Safe browsing enablement
 *
 * The check analyzes both the app's manifest and attempts to inspect WebView configurations
 * to identify potential security risks.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see WebView
 * @see WebSettings
 */
internal class WebViewSecurityCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the WebView security check.
     *
     * This method evaluates various aspects of WebView configuration and usage, returning a list of [SecurityIssue]s
     * if any vulnerabilities are found. The check includes:
     *
     * 1. Checking if WebView is used in the application
     * 2. Analyzing WebView-related permissions in the manifest
     * 3. Inspecting WebView configurations for potential security risks
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        if (isWebViewUsed()) {
            issues.addAll(checkWebViewPermissions())
            issues.addAll(checkWebViewConfigurations())
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
     * Checks WebView-related permissions in the manifest.
     *
     * @return A list of [SecurityIssue]s related to WebView permissions.
     */
    private fun checkWebViewPermissions(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageInfo =
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_PERMISSIONS,
            )

        packageInfo.requestedPermissions?.forEach { permission ->
            when (permission) {
                "android.permission.INTERNET" -> {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.LOW,
                            description = "Internet permission is granted, which is required for WebView but also increases attack surface",
                            recommendation = "Ensure that WebView is properly secured and only loads content from trusted sources.",
                        ),
                    )
                }
            }
        }
        return issues
    }

    /**
     * Inspects WebView configurations for potential security risks.
     *
     * @return A list of [SecurityIssue]s related to WebView configurations.
     */
    private fun checkWebViewConfigurations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        try {
            val webView = WebView(context)
            val settings = webView.settings

            if (settings.javaScriptEnabled) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "JavaScript is enabled in WebView",
                        recommendation = "Disable JavaScript if not necessary, or ensure it's only enabled for trusted content.",
                    ),
                )
            }

            if (settings.allowFileAccess) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "File access is allowed in WebView",
                        recommendation = "Disable file access in WebView unless absolutely necessary.",
                    ),
                )
            }

            if (settings.allowContentAccess) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Content access is allowed in WebView",
                        recommendation = "Disable content access in WebView if not required.",
                    ),
                )
            }

            if (settings.allowFileAccessFromFileURLs) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "File access from file URLs is allowed in WebView",
                        recommendation = "Disable file access from file URLs to prevent potential security vulnerabilities.",
                    ),
                )
            }

            if (settings.allowUniversalAccessFromFileURLs) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Universal access from file URLs is allowed in WebView",
                        recommendation = "Disable universal access from file URLs to prevent potential security vulnerabilities.",
                    ),
                )
            }

            if (settings.mixedContentMode == WebSettings.MIXED_CONTENT_ALWAYS_ALLOW) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Mixed content is always allowed in WebView",
                        recommendation = "Set mixed content mode to MIXED_CONTENT_NEVER_ALLOW or handle with caution.",
                    ),
                )
            }

            // Check for safe browsing
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                if (!settings.safeBrowsingEnabled) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "Safe Browsing is not enabled in WebView",
                            recommendation = "Enable Safe Browsing in WebView for enhanced security.",
                        ),
                    )
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to inspect WebView settings: ${e.message}",
                    recommendation = "Ensure WebView is properly configured in your application.",
                ),
            )
        }
        return issues
    }
}
