package com.androidacestudio.sentinelarmor

import android.content.Context
import android.content.SharedPreferences
import java.io.File
import java.io.FileInputStream
import kotlin.math.min

/**
 * A security check that identifies potentially insecure data storage practices in Android applications.
 *
 * This check examines various data storage mechanisms commonly used in Android apps:
 * - SharedPreferences
 * - Internal storage files
 * - External storage usage
 * - Database files
 *
 * The check looks for indicators of insecure practices such as storing sensitive data in
 * plain text, using mode MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE, or storing sensitive
 * data in external storage.
 *
 * @property context The Android application context, used to access app-specific storage locations and preferences.
 *
 * @see SecurityCheck
 * @see SharedPreferences
 */
internal class InsecureDataStorageCheck(private val context: Context) : SecurityCheck {

    companion object {
        private val SENSITIVE_KEYS = listOf("password", "credit_card", "ssn", "api_key", "token")
        private const val PREFERENCES_NAME = "app_preferences"
    }

    /**
     * Performs the insecure data storage check.
     *
     * This method evaluates various data storage practices and returns a list of [SecurityIssue]s
     * if any vulnerabilities are found. The check includes:
     *
     * 1. Examining SharedPreferences for sensitive data stored in plain text
     * 2. Checking for insecure file permissions in internal storage
     * 3. Detecting usage of external storage for sensitive data
     * 4. Identifying potentially insecure database files
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkSharedPreferences())
        issues.addAll(checkInternalStorage())
        issues.addAll(checkExternalStorage())
        issues.addAll(checkDatabases())

        return issues
    }

    /**
     * Checks SharedPreferences for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to SharedPreferences.
     */
    private fun checkSharedPreferences(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val prefs = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

        SENSITIVE_KEYS.forEach { key ->
            if (prefs.contains(key)) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Potentially sensitive data found in SharedPreferences: $key",
                        recommendation = "Avoid storing sensitive data in SharedPreferences. Use Android Keystore System for secure storage."
                    )
                )
            }
        }

        return issues
    }

    /**
     * Checks internal storage for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to internal storage.
     */
    private fun checkInternalStorage(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val internalDir = context.filesDir

        internalDir.listFiles()?.forEach { file ->
            if (file.canRead() && !file.canWrite()) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "File in internal storage has insecure permissions: ${file.name}",
                        recommendation = "Ensure proper file permissions. Use Context.MODE_PRIVATE for file operations."
                    )
                )
            }
        }

        return issues
    }

    /**
     * Checks external storage usage for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to external storage.
     */
    private fun checkExternalStorage(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val externalDir = context.getExternalFilesDir(null)

        if (externalDir != null && externalDir.listFiles()?.isNotEmpty() == true) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "App is using external storage, which can be insecure",
                    recommendation = "Avoid storing sensitive data in external storage. Use internal storage or encrypted files for sensitive data."
                )
            )
        }

        return issues
    }

    /**
     * Checks database files for potential security issues.
     *
     * @return A list of [SecurityIssue]s related to database storage.
     */
    private fun checkDatabases(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val databaseList = context.databaseList()

        databaseList.forEach { dbName ->
            val dbFile = context.getDatabasePath(dbName)
            if (dbFile.exists() && !isEncrypted(dbFile)) {
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Potentially unencrypted database found: $dbName",
                        recommendation = "Consider using encrypted databases or SQLCipher for sensitive data storage."
                    )
                )
            }
        }

        return issues
    }

    /**
     * Checks if a file is likely to be encrypted using multiple heuristics.
     *
     * This method uses several techniques to determine if a file is potentially encrypted:
     * 1. Checks file extension and name for common encryption indicators.
     * 2. Analyzes file entropy to detect randomness associated with encryption.
     * 3. Looks for known file signatures (magic numbers) of common file types.
     * 4. Checks for repetitive patterns which are unlikely in encrypted data.
     *
     * @param file The file to check.
     * @return true if the file is likely to be encrypted, false otherwise.
     */
    private fun isEncrypted(file: File): Boolean {
        // Check file extension and name
        if (file.extension == "enc" || file.name.contains("encrypted", ignoreCase = true)) {
            return true
        }

        // Read the first 4KB of the file for analysis
        val buffer = ByteArray(4096)
        FileInputStream(file).use { input ->
            val bytesRead = input.read(buffer)
            if (bytesRead > 0) {
                // Check file entropy
                if (calculateEntropy(buffer.sliceArray(0 until bytesRead)) > 7.5) {
                    return true
                }

                // Check for common file signatures
                if (hasCommonFileSignature(buffer.sliceArray(0 until min(bytesRead, 8)))) {
                    return false
                }

                // Check for repetitive patterns
                if (hasRepetitivePatterns(buffer.sliceArray(0 until bytesRead))) {
                    return false
                }
            }
        }

        // If none of the above checks were conclusive, err on the side of caution
        return true
    }

    /**
     * Calculates the entropy of the given byte array.
     * Higher entropy (closer to 8) suggests more randomness, which is typical of encrypted data.
     */
    private fun calculateEntropy(data: ByteArray): Double {
        val frequency = IntArray(256) { 0 }
        data.forEach { frequency[it.toInt() and 0xFF]++ }

        return frequency.fold(0.0) { entropy, freq ->
            val p = freq.toDouble() / data.size
            entropy - if (p > 0) p * log2(p) else 0.0
        }
    }

    /**
     * Checks if the file starts with common file signatures (magic numbers).
     * If it does, it's likely not encrypted.
     */
    private fun hasCommonFileSignature(header: ByteArray): Boolean {
        val signatures = mapOf(
            "FFD8FF" to "JPEG",
            "89504E47" to "PNG",
            "47494638" to "GIF",
            "25504446" to "PDF",
            "504B0304" to "ZIP"
            // TODO Add more signatures as needed in future
        )

        val headerHex = header.joinToString("") { "%02X".format(it) }
        return signatures.any { (signature, _) -> headerHex.startsWith(signature) }
    }

    /**
     * Checks for repetitive patterns in the data.
     * Encrypted data typically doesn't have repetitive patterns.
     */
    private fun hasRepetitivePatterns(data: ByteArray): Boolean {
        val patternSize = 3
        val threshold = 10
        var repetitions = 0

        for (i in 0 until data.size - patternSize) {
            val pattern = data.sliceArray(i until i + patternSize)
            var patternCount = 0
            var j = i + patternSize
            while (j < data.size - patternSize) {
                if (data.sliceArray(j until j + patternSize).contentEquals(pattern)) {
                    patternCount++
                    j += patternSize
                } else {
                    break
                }
            }
            if (patternCount > threshold) {
                repetitions++
            }
        }

        return repetitions > 5 // TODO Arbitrary threshold, adjust based on testing input
    }

    private fun log2(x: Double): Double = kotlin.math.log(x, 2.0)
}
