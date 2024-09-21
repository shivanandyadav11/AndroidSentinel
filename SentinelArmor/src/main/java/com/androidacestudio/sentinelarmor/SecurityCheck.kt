package com.androidacestudio.sentinelarmor

/**
 * SecurityCheck
 *
 * This interface defines the contract for all security checks within the SentinelArmor library.
 * It provides a standardized way to implement various security checks for Android applications,
 * ensuring consistency and modularity in the security analysis process.
 *
 * Each implementation of this interface represents a specific security check, focusing on
 * a particular aspect of Android application security. These checks can include, but are not
 * limited to:
 * - Permission usage analysis
 * - Cryptography implementation verification
 * - Data storage security assessment
 * - Network communication security evaluation
 * - Component exposure checks (Activities, Services, Broadcast Receivers, etc.)
 * - Third-party library security audits
 *
 * Key aspects:
 * - Provides a uniform method [check] for performing security analysis
 * - Allows for easy addition of new security checks to the SentinelArmor toolkit
 * - Facilitates modular and extensible security analysis architecture
 *
 * Usage:
 * Implementations of this interface are typically instantiated and invoked by the
 * [AndroidSentinel] implementation. Each check is executed independently and contributes
 * its findings to the overall security analysis.
 *
 * Example implementation:
 * ```
 * class PermissionCheck : SecurityCheck {
 *     override fun check(): List<SecurityIssue> {
 *         // Perform permission-related security checks
 *         // Return a list of identified security issues
 *     }
 * }
 * ```
 *
 * Note: Implementers of this interface should ensure that their check() method is
 * self-contained and does not rely on the execution of other checks. This allows for
 * parallel execution of checks if desired and maintains the modularity of the system.
 *
 * @see SecurityIssue
 * @see AndroidSentinel
 */
interface SecurityCheck {
    /**
     * Performs the security check and returns a list of identified security issues.
     *
     * This method encapsulates the logic for a specific security check. It should analyze
     * the relevant aspects of the Android application and identify any security vulnerabilities
     * or misconfigurations related to its particular domain.
     *
     * The implementation should:
     * 1. Perform the necessary analysis or checks
     * 2. Identify any security issues
     * 3. Create [SecurityIssue] objects for each identified issue
     * 4. Return all identified issues as a list
     *
     * @return A list of [SecurityIssue] objects representing the security vulnerabilities
     *         or misconfigurations identified by this check. Returns an empty list if no
     *         issues are found.
     *
     * Note: Implementations should handle exceptions internally and report them as
     * [SecurityIssue] objects where appropriate, rather than throwing exceptions.
     * This ensures that one problematic check doesn't halt the entire security analysis process.
     *
     * @see SecurityIssue
     */
    fun check(): List<SecurityIssue>
}
