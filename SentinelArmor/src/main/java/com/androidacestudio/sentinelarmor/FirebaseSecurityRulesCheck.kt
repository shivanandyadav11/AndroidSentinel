package com.androidacestudio.sentinelarmor

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.database.FirebaseDatabase
import com.google.firebase.firestore.FirebaseFirestore
import dalvik.system.DexFile
import java.io.File

/**
 * A security check that examines the usage of Firebase in Android applications and attempts to
 * identify potential issues related to Firebase Security Rules.
 *
 * This check analyzes various aspects of Firebase usage:
 * - Detection of Firebase SDK in the application
 * - Examination of Firebase Realtime Database usage
 * - Analysis of Cloud Firestore usage
 * - Identification of potential security rule misconfigurations
 * - Detection of client-side security enforcement attempts
 *
 * The check aims to identify potential vulnerabilities related to Firebase Security Rules
 * and database access patterns.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see FirebaseApp
 * @see FirebaseDatabase
 * @see FirebaseFirestore
 */
internal class FirebaseSecurityRulesCheck(
    private val context: Context,
) : SecurityCheck {
    /**
     * Performs the Firebase Security Rules check.
     *
     * This method evaluates various aspects of Firebase usage in the application,
     * returning a list of [SecurityIssue]s if any potential vulnerabilities or misconfigurations are found.
     * The check includes:
     *
     * 1. Detecting Firebase SDK usage in the application
     * 2. Analyzing Firebase Realtime Database access patterns
     * 3. Examining Cloud Firestore usage and potential misconfigurations
     * 4. Identifying client-side attempts at security enforcement
     * 5. Checking for proper initialization and configuration of Firebase
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        if (isFirebaseUsed()) {
            issues.addAll(checkFirebaseInitialization())
            issues.addAll(checkRealtimeDatabaseUsage())
            issues.addAll(checkFirestoreUsage())
            issues.addAll(checkClientSideSecurityEnforcement())
        }
        return issues
    }

    /**
     * Checks if Firebase SDK is used in the application.
     *
     * @return true if Firebase is used, false otherwise.
     */
    private fun isFirebaseUsed(): Boolean =
        try {
            Class.forName("com.google.firebase.FirebaseApp")
            true
        } catch (e: ClassNotFoundException) {
            false
        }

    /**
     * Checks for proper Firebase initialization and configuration.
     *
     * @return A list of [SecurityIssue]s related to Firebase initialization.
     */
    private fun checkFirebaseInitialization(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        try {
            val firebaseApp = FirebaseApp.getInstance()
            if (firebaseApp == null) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Firebase is not properly initialized",
                        recommendation = "Ensure Firebase is initialized correctly in your application.",
                    ),
                )
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Unable to verify Firebase initialization: ${e.message}",
                    recommendation = "Check Firebase initialization process and ensure it's done correctly.",
                ),
            )
        }
        return issues
    }

    /**
     * Analyzes Firebase Realtime Database usage for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to Realtime Database usage.
     */
    private fun checkRealtimeDatabaseUsage(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("FirebaseDatabase.getInstance()")) {
                            if (!body.contains(".getReference()") && !body.contains(".child(")) {
                                issues.add(
                                    SecurityIssue(
                                        severity = Severity.HIGH,
                                        description = "Potential unrestricted Realtime Database access in ${clazz.simpleName}.${method.name}",
                                        recommendation = "Ensure proper security rules are set in Firebase console and use specific database references.",
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
                    description = "Unable to analyze Realtime Database usage: ${e.message}",
                    recommendation = "Manually review Realtime Database access patterns and security rules.",
                ),
            )
        }
        return issues
    }

    /**
     * Examines Cloud Firestore usage for potential security misconfigurations.
     *
     * @return A list of [SecurityIssue]s related to Firestore usage.
     */
    private fun checkFirestoreUsage(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if (body.contains("FirebaseFirestore.getInstance()")) {
                            if (body.contains(".collection(") && !body.contains(".document(")) {
                                issues.add(
                                    SecurityIssue(
                                        severity = Severity.MEDIUM,
                                        description = "Potential broad Firestore collection access in ${clazz.simpleName}.${method.name}",
                                        recommendation = "Ensure Firestore security rules properly restrict access to collections and documents.",
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
                    description = "Unable to analyze Firestore usage: ${e.message}",
                    recommendation = "Manually review Firestore access patterns and security rules.",
                ),
            )
        }
        return issues
    }

    /**
     * Identifies attempts at client-side security enforcement, which should be avoided.
     *
     * @return A list of [SecurityIssue]s related to client-side security enforcement.
     */
    private fun checkClientSideSecurityEnforcement(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()
                        if ((body.contains("FirebaseDatabase") || body.contains("FirebaseFirestore")) &&
                            (body.contains("if (") || body.contains("check") || body.contains("validate"))
                        ) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "Potential client-side security enforcement detected in ${clazz.simpleName}.${method.name}",
                                    recommendation = "Avoid client-side security checks. Implement all security rules server-side in Firebase Security Rules.",
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
                    description = "Unable to analyze for client-side security enforcement: ${e.message}",
                    recommendation = "Manually review code for any client-side attempts at enforcing security rules.",
                ),
            )
        }
        return issues
    }
}
