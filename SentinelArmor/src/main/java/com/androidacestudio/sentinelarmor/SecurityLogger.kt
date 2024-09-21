package com.androidacestudio.sentinelarmor

import android.util.Log

/**
 * SecurityLogger
 *
 * This object provides a centralized logging mechanism for security-related issues
 * detected by the SentinelArmor library. It encapsulates the logging logic and
 * ensures consistent formatting of security issue logs.
 *
 * The SecurityLogger uses Android's built-in Log class to output warnings for each
 * security issue. This allows for easy integration with Android's logging system
 * and enables developers to view security issues in logcat or other log viewers.
 *
 * Key features:
 * - Singleton object for global access
 * - Consistent logging format for all security issues
 * - Uses Android's Log.w (warning level) for all security issues
 * - Encapsulates the TAG used for logging
 *
 * Usage:
 * This logger is typically used after running security checks to log any detected issues.
 * It can be called from anywhere in the SentinelArmor library or from client code that
 * uses the library.
 *
 * Example usage:
 * ```
 * val securityIssue = SecurityIssue(Severity.HIGH, "Insecure data storage", "Use encrypted SharedPreferences")
 * SecurityLogger.logIssue(securityIssue)
 * ```
 *
 * Note: While this logger outputs to Android's logging system by default, it can be
 * extended or modified to support other logging mechanisms if needed (e.g., writing to a file,
 * sending logs to a remote server).
 *
 * @see SecurityIssue
 * @see android.util.Log
 */
object SecurityLogger {
    /**
     * Tag used for Android logging.
     *
     * This constant defines the tag that will be used in all log messages generated
     * by this logger. It helps in filtering and identifying logs specific to
     * AndroidSentinel in the logcat output.
     */
    private const val TAG = "AndroidSentinel"

    /**
     * Logs a security issue.
     *
     * This function takes a [SecurityIssue] object and logs its details as a warning
     * message using Android's Log system. The log message includes the severity,
     * description, and recommendation for the security issue.
     *
     * The log message is formatted as follows:
     * "Security Issue - Severity: [SEVERITY], Description: [DESCRIPTION], Recommendation: [RECOMMENDATION]"
     *
     * @param issue The [SecurityIssue] to be logged. This object should contain
     *              all the relevant details about the detected security issue.
     *
     * Note: This method uses Log.w (warning level) for all security issues, regardless
     * of their severity. This ensures that all security-related logs are easily
     * visible and not filtered out by default log settings.
     *
     * @see SecurityIssue
     */
    fun logIssue(issue: SecurityIssue) {
        Log.w(
            TAG,
            "Security Issue - Severity: ${issue.severity}, Description: ${issue.description}, Recommendation: ${issue.recommendation}",
        )
    }
}
