package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.InputStream

/**
 * A security check that examines the Network Security Configuration in Android applications.
 *
 * This check analyzes various aspects of the Network Security Configuration:
 * - Presence and proper declaration of the network security config file
 * - Use of cleartext traffic
 * - Certificate pinning configuration
 * - Trust anchors and custom certificate authorities
 * - Debug-override settings
 *
 * The check aims to identify potential vulnerabilities or misconfigurations in
 * the app's network security settings.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 */
internal class NetworkSecurityConfigCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the Network Security Configuration check.
     *
     * This method evaluates various aspects of the Network Security Configuration,
     * returning a list of [SecurityIssue]s if any vulnerabilities or misconfigurations are found.
     * The check includes:
     *
     * 1. Verifying the presence and declaration of the network security config file
     * 2. Analyzing cleartext traffic settings
     * 3. Examining certificate pinning configurations
     * 4. Checking trust anchors and custom certificate authorities
     * 5. Inspecting debug-override settings
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        val configResourceId = getNetworkSecurityConfigResourceId()
        if (configResourceId == 0) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Network Security Configuration is not set",
                    recommendation = "Implement a Network Security Configuration to enhance app's network security.",
                ),
            )
            return issues
        }

        val inputStream = context.resources.openRawResource(configResourceId)
        issues.addAll(analyzeNetworkSecurityConfig(inputStream))

        return issues
    }

    /**
     * Retrieves the resource ID of the Network Security Configuration file.
     *
     * @return The resource ID of the config file, or 0 if not found.
     */
    private fun getNetworkSecurityConfigResourceId(): Int {
        try {
            val applicationInfo: ApplicationInfo =
                context.packageManager.getApplicationInfo(
                    context.packageName,
                    PackageManager.GET_META_DATA,
                )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // For Android 7.0 (API 24) and above
                val networkSecurityConfigField =
                    applicationInfo.javaClass.getField("networkSecurityConfigRes")
                return networkSecurityConfigField.getInt(applicationInfo)
            } else {
                // For versions below Android 7.0
                return applicationInfo.metaData?.getInt("android:network_security_config", 0) ?: 0
            }
        } catch (e: PackageManager.NameNotFoundException) {
            // This shouldn't happen as we're querying our own package
            return 0
        } catch (_: Exception) {
            return 0
        }
    }

    /**
     * Analyzes the contents of the Network Security Configuration file.
     *
     * @param inputStream The input stream of the config file.
     * @return A list of [SecurityIssue]s based on the analysis.
     */
    private fun analyzeNetworkSecurityConfig(inputStream: InputStream): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val factory = XmlPullParserFactory.newInstance()
        val parser = factory.newPullParser()
        parser.setInput(inputStream, null)

        var cleartextPermitted = false
        var certificatePinningFound = false
        var customTrustAnchorsFound = false
        var debugOverridesFound = false

        while (parser.eventType != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType == XmlPullParser.START_TAG) {
                when (parser.name) {
                    "base-config", "domain-config" -> {
                        val cleartextAttr =
                            parser.getAttributeValue(null, "cleartextTrafficPermitted")
                        if (cleartextAttr == "true") {
                            cleartextPermitted = true
                        }
                    }

                    "pin-set" -> {
                        certificatePinningFound = true
                    }

                    "trust-anchors" -> {
                        customTrustAnchorsFound = true
                    }

                    "debug-overrides" -> {
                        debugOverridesFound = true
                    }
                }
            }
            parser.next()
        }

        if (cleartextPermitted) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Cleartext traffic is permitted",
                    recommendation = "Disable cleartext traffic and use HTTPS for all network communications.",
                ),
            )
        }

        if (!certificatePinningFound) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Certificate pinning is not configured",
                    recommendation = "Consider implementing certificate pinning for critical domains.",
                ),
            )
        }

        if (customTrustAnchorsFound) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Custom trust anchors are defined",
                    recommendation = "Ensure that custom trust anchors are necessary and securely managed.",
                ),
            )
        }

        if (debugOverridesFound && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Debug overrides are present",
                    recommendation = "Ensure debug overrides are removed in release builds.",
                ),
            )
        }

        return issues
    }
}
