package com.androidacestudio.sentinelarmor

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.view.Window
import android.view.WindowManager
import java.io.File
import java.util.jar.JarFile
import dalvik.system.DexFile
import java.util.Locale

/**
 * A security check that identifies potential vulnerabilities related to tapjacking (clickjacking) in Android applications.
 *
 * This check examines various aspects of window and view configurations:
 * - Use of FLAG_SECURE to prevent screen capture
 * - Overlay permission usage
 * - TouchFilter usage for filtering touch events
 * - Custom tapjacking protection implementations
 *
 * The check analyzes both the app's manifest and attempts to inspect activity configurations
 * to identify potential security risks related to tapjacking.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see Window
 * @see WindowManager
 */
internal class TapjackingCheck(private val context: Context) : SecurityCheck {

    /**
     * Performs the tapjacking security check.
     *
     * This method evaluates various aspects of the application's configuration and usage,
     * returning a list of [SecurityIssue]s if any vulnerabilities are found. The check includes:
     *
     * 1. Analyzing overlay-related permissions in the manifest
     * 2. Inspecting activity configurations for tapjacking protections
     * 3. Checking for custom tapjacking protection implementations
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkOverlayPermissions())
        issues.addAll(checkActivityConfigurations())
        issues.addAll(checkCustomTapjackingProtection())

        return issues
    }

    /**
     * Checks overlay-related permissions in the manifest.
     *
     * @return A list of [SecurityIssue]s related to overlay permissions.
     */
    private fun checkOverlayPermissions(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageInfo = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS
        )

        packageInfo.requestedPermissions?.forEach { permission ->
            when (permission) {
                "android.permission.SYSTEM_ALERT_WINDOW" -> {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "App requests SYSTEM_ALERT_WINDOW permission, which can be used for overlay attacks",
                            recommendation = "Ensure this permission is absolutely necessary. If used, implement additional security measures to prevent misuse."
                        )
                    )
                }
            }
        }
        return issues
    }

    /**
     * Inspects activity configurations for tapjacking protections.
     *
     * @return A list of [SecurityIssue]s related to activity configurations.
     */
    private fun checkActivityConfigurations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_ACTIVITIES
            )
            val activityInfos = packageInfo.activities ?: return issues

            activityInfos.forEach { activityInfo ->
                val activityClass = Class.forName(activityInfo.name)
                val activity =
                    Activity::class.java.cast(activityClass.getDeclaredConstructor().newInstance())

                if (activity != null) {
                    if ((activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) == 0) {
                        issues.add(
                            SecurityIssue(
                                severity = Severity.HIGH,
                                description = "FLAG_SECURE is not set for activity: ${activityInfo.name}",
                                recommendation = "Set FLAG_SECURE on the activity's window to prevent screen capture and enhance protection against tapjacking."
                            )
                        )
                    }
                }

                // Check for filterTouchesWhenObscured
                val contentView = activity?.findViewById<android.view.View>(android.R.id.content)
                if (contentView != null && !contentView.filterTouchesWhenObscured) {
                    issues.add(
                        SecurityIssue(
                            severity = Severity.MEDIUM,
                            description = "filterTouchesWhenObscured is not enabled for activity: ${activityInfo.name}",
                            recommendation = "Enable filterTouchesWhenObscured on the root view to filter touch events when the view's window is obscured."
                        )
                    )
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to inspect activity configurations: ${e.message}",
                    recommendation = "Ensure all activities implement proper tapjacking protections."
                )
            )
        }
        return issues
    }

    /**
     * Checks for custom tapjacking protection implementations.
     *
     * This function performs a more thorough analysis to detect custom tapjacking protections
     * that may have been implemented in the app. It looks for:
     * 1. Custom view classes that might implement touch filtering
     * 2. Usage of SystemAlert or TYPE_APPLICATION_OVERLAY window types
     * 3. Custom security-related method names
     * 4. Reflection usage that might indicate runtime security checks
     *
     * @return A list of [SecurityIssue]s related to custom tapjacking protections.
     */
    private fun checkCustomTapjackingProtection(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val apkFile = File(packageInfo.applicationInfo.sourceDir)

            // Check for custom View classes
            val customViewClasses = findCustomViewClasses(apkFile)
            if (customViewClasses.isNotEmpty()) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.LOW,
                        description = "Custom View classes detected: ${customViewClasses.joinToString()}",
                        recommendation = "Verify that these custom View classes implement proper touch event filtering."
                    )
                )
            }

            // Check for overlay window usage
            if (checkForOverlayWindowUsage(apkFile)) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Usage of overlay windows detected",
                        recommendation = "Ensure overlay windows are used securely and don't introduce tapjacking vulnerabilities."
                    )
                )
            }

            // Check for security-related method names
            val securityMethods = findSecurityRelatedMethods(apkFile)
            if (securityMethods.isNotEmpty()) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.LOW,
                        description = "Potential custom security methods detected: ${securityMethods.joinToString()}",
                        recommendation = "Review these methods to ensure they provide adequate tapjacking protection."
                    )
                )
            }

            // Check for reflection usage
            if (checkForReflectionUsage(apkFile)) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.LOW,
                        description = "Reflection usage detected",
                        recommendation = "Verify that reflection is not used to bypass security measures or implement insecure dynamic behavior."
                    )
                )
            }

        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Error analyzing custom tapjacking protections: ${e.message}",
                    recommendation = "Manually review the app for custom tapjacking protection implementations."
                )
            )
        }
        return issues
    }

    /**
     * Finds custom View classes in the app's APK file.
     */
    private fun findCustomViewClasses(apkFile: File): List<String> {
        val customViews = mutableListOf<String>()
        JarFile(apkFile).use { jar ->
            jar.entries().asSequence().forEach { entry ->
                if (entry.name.endsWith(".class") && !entry.name.startsWith("android/")) {
                    val className = entry.name.replace('/', '.').removeSuffix(".class")
                    if (className.endsWith("View") || className.contains("TouchListener")) {
                        customViews.add(className)
                    }
                }
            }
        }
        return customViews
    }

    /**
     * Checks for usage of overlay window types.
     */
    private fun checkForOverlayWindowUsage(apkFile: File): Boolean {
        var usesOverlay = false
        DexFile(apkFile).entries().toList().forEach { className ->
            val cls = Class.forName(className)
            cls.declaredMethods.forEachIndexed { _, method ->
                if (method.name.contains("addView") || method.name.contains("setType")) {
                    val body = method.toGenericString()
                    if (body.contains("TYPE_APPLICATION_OVERLAY") || body.contains("TYPE_SYSTEM_ALERT")) {
                        usesOverlay = true
                        return@forEachIndexed
                    }
                }
            }
            if (usesOverlay) return@forEach
        }
        return usesOverlay
    }

    /**
     * Finds potential security-related method names.
     */
    private fun findSecurityRelatedMethods(apkFile: File): List<String> {
        val securityMethods = mutableListOf<String>()
        DexFile(apkFile).entries().toList().forEach { className ->
            val cls = Class.forName(className)
            cls.declaredMethods.forEach { method ->
                if (method.name.lowercase(Locale.ROOT).contains("security") ||
                    method.name.lowercase(Locale.ROOT).contains("protect") ||
                    method.name.lowercase(Locale.ROOT).contains("filter")
                ) {
                    securityMethods.add("${cls.simpleName}.${method.name}")
                }
            }
        }
        return securityMethods
    }

    /**
     * Checks for usage of reflection, which might indicate runtime security checks.
     */
    private fun checkForReflectionUsage(apkFile: File): Boolean {
        DexFile(apkFile).entries().toList().forEach { className ->
            val cls = Class.forName(className)
            cls.declaredMethods.forEach { method ->
                val body = method.toGenericString()
                if (body.contains("java.lang.reflect")) {
                    return true
                }
            }
        }
        return false
    }
}