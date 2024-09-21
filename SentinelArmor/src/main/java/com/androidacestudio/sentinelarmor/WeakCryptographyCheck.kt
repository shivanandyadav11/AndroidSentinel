package com.androidacestudio.sentinelarmor

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import dalvik.system.DexFile
import java.io.File
import java.lang.reflect.Method
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.interfaces.RSAKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * A security check that identifies the use of weak cryptographic algorithms or practices in Android applications.
 *
 * This check examines various aspects of cryptography usage:
 * - Weak hash functions (e.g., MD5, SHA-1)
 * - Insecure cipher algorithms (e.g., DES, RC4)
 * - Weak cipher modes (e.g., ECB mode)
 * - Short key lengths
 * - Use of static initialization vectors (IVs)
 * - Presence of custom cryptographic implementations
 *
 * The check analyzes both the app's code and its dependencies to identify potential vulnerabilities.
 *
 * @property context The Android application context, used to access app information and resources.
 *
 * @see SecurityCheck
 * @see MessageDigest
 * @see Cipher
 */
internal class WeakCryptographyCheck(
    private val context: Context,
) : SecurityCheck {
    companion object {
        private val WEAK_HASH_ALGORITHMS = setOf("MD5", "SHA-1")
        private val WEAK_CIPHER_ALGORITHMS = setOf("DES", "RC4", "Blowfish")
        private val WEAK_CIPHER_MODES = setOf("ECB")
        private const val MIN_RSA_KEY_SIZE = 2048
        private const val MIN_AES_KEY_SIZE = 128
    }

    /**
     * Performs the weak cryptography check.
     *
     * This method evaluates various aspects of cryptographic usage and returns a list of [SecurityIssue]s
     * if any vulnerabilities are found. The check includes:
     *
     * 1. Identifying the use of weak hash functions
     * 2. Detecting insecure cipher algorithms
     * 3. Checking for weak cipher modes
     * 4. Verifying key lengths
     * 5. Looking for potential misuse of initialization vectors
     * 6. Detecting custom cryptographic implementations
     *
     * @return A list of [SecurityIssue]s. If the list is empty, no security issues were detected.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        issues.addAll(checkWeakHashFunctions())
        issues.addAll(checkInsecureCipherAlgorithms())
        issues.addAll(checkWeakCipherModes())
        issues.addAll(checkKeyLengths())
        issues.addAll(checkInitializationVectors())
        issues.addAll(checkCustomCryptoImplementations())
        return issues
    }

    /**
     * Checks for the use of weak hash functions.
     *
     * @return A list of [SecurityIssue]s related to weak hash functions.
     */
    private fun checkWeakHashFunctions(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        WEAK_HASH_ALGORITHMS.forEach { algorithm ->
            try {
                MessageDigest.getInstance(algorithm)
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Weak hash function detected: $algorithm",
                        recommendation = "Replace $algorithm with a stronger alternative like SHA-256 or SHA-3.",
                    ),
                )
            } catch (e: Exception) {
                // Algorithm not available, which is good in this case
            }
        }
        return issues
    }

    /**
     * Checks for the use of insecure cipher algorithms.
     *
     * @return A list of [SecurityIssue]s related to insecure cipher algorithms.
     */
    private fun checkInsecureCipherAlgorithms(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        WEAK_CIPHER_ALGORITHMS.forEach { algorithm ->
            try {
                Cipher.getInstance(algorithm)
                issues.add(
                    SecurityIssue(
                        severity = Severity.HIGH,
                        description = "Insecure cipher algorithm detected: $algorithm",
                        recommendation = "Replace $algorithm with a secure alternative like AES.",
                    ),
                )
            } catch (e: Exception) {
                // Algorithm not available, which is good in this case
            }
        }
        return issues
    }

    /**
     * Checks for the use of weak cipher modes.
     *
     * @return A list of [SecurityIssue]s related to weak cipher modes.
     */
    private fun checkWeakCipherModes(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        WEAK_CIPHER_MODES.forEach { mode ->
            try {
                Cipher.getInstance("AES/$mode/PKCS5Padding")
                issues.add(
                    SecurityIssue(
                        severity = Severity.MEDIUM,
                        description = "Weak cipher mode detected: $mode",
                        recommendation = "Avoid using $mode mode. Prefer GCM or CBC mode with proper IV handling.",
                    ),
                )
            } catch (e: Exception) {
                // Mode not available, which is good in this case
            }
        }
        return issues
    }

    /**
     * Checks for potentially insufficient key lengths by analyzing KeyStore entries
     * and inspecting Cipher instances.
     *
     * @return A list of [SecurityIssue]s related to insufficient key lengths.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun checkKeyLengths(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        // Check KeyStore entries
        issues.addAll(checkKeyStoreEntries())

        // Check Cipher instances
        issues.addAll(checkCipherInstances())

        return issues
    }

    /**
     * Checks key lengths of entries in the Android KeyStore.
     */
    private fun checkKeyStoreEntries(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            keyStore.aliases().toList().forEach { alias ->
                when (val entry = keyStore.getEntry(alias, null)) {
                    is KeyStore.PrivateKeyEntry -> {
                        when (val privateKey = entry.privateKey) {
                            is RSAKey -> {
                                val keySize = privateKey.modulus.bitLength()
                                if (keySize < MIN_RSA_KEY_SIZE) {
                                    issues.add(
                                        SecurityIssue(
                                            severity = Severity.HIGH,
                                            description = "RSA key with insufficient length detected: $keySize bits for alias '$alias'",
                                            recommendation = "Use RSA keys with at least $MIN_RSA_KEY_SIZE bits.",
                                        ),
                                    )
                                }
                            }

                            else -> {
                                // Handle other key types (e.g., EC) if necessary
                            }
                        }
                    }

                    is KeyStore.SecretKeyEntry -> {
                        val secretKey = entry.secretKey
                        val keySize = secretKey.encoded.size * 8
                        if (keySize < MIN_AES_KEY_SIZE) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "AES key with insufficient length detected: $keySize bits for alias '$alias'",
                                    recommendation = "Use AES keys with at least $MIN_AES_KEY_SIZE bits.",
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
                    description = "Unable to analyze KeyStore entries: ${e.message}",
                    recommendation = "Ensure proper KeyStore usage and permissions.",
                ),
            )
        }
        return issues
    }

    /**
     * Checks for potentially insufficient key lengths by analyzing Cipher instances.
     *
     * This method attempts to create Cipher instances for common algorithms (AES, RSA)
     * and checks the length of the keys used. It reports issues for keys that don't
     * meet the minimum length requirements.
     *
     * @return A list of [SecurityIssue]s related to insufficient key lengths.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun checkCipherInstances(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val algorithms = listOf("AES", "RSA")

        algorithms.forEach { algorithm ->
            try {
                val cipher = Cipher.getInstance(algorithm)
                val keyGenParameterSpec =
                    when (algorithm) {
                        "AES" ->
                            KeyGenParameterSpec
                                .Builder(
                                    "temp_key",
                                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                                ).setKeySize(128)
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                .build()

                        "RSA" ->
                            KeyGenParameterSpec
                                .Builder(
                                    "temp_key",
                                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                                ).setKeySize(2048)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                                .build()

                        else -> null
                    }

                if (keyGenParameterSpec != null) {
                    val key = generateKey(algorithm, keyGenParameterSpec)
                    if (key != null) {
                        cipher.init(Cipher.ENCRYPT_MODE, key)
                        val keySize = getKeySize(key)

                        val minSize =
                            when (algorithm) {
                                "AES" -> MIN_AES_KEY_SIZE
                                "RSA" -> MIN_RSA_KEY_SIZE
                                else -> 0
                            }

                        if (keySize < minSize) {
                            issues.add(
                                SecurityIssue(
                                    severity = Severity.HIGH,
                                    description = "$algorithm key with insufficient length detected: $keySize bits",
                                    recommendation = "Use $algorithm keys with at least $minSize bits.",
                                ),
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                // Algorithm not available or error in analysis
            }
        }
        return issues
    }

    /**
     * Generates a cryptographic key based on the specified algorithm and parameters.
     *
     * This function creates either a symmetric key (for AES) or an asymmetric key pair (for RSA)
     * using the provided algorithm and key generation parameters.
     *
     * @param algorithm The cryptographic algorithm to use ("AES" or "RSA").
     * @param spec The key generation parameter specification.
     * @return The generated [Key] object, or null if the algorithm is not supported.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKey(
        algorithm: String,
        spec: KeyGenParameterSpec,
    ): Key? =
        when (algorithm) {
            "AES" -> {
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
                keyGen.init(spec)
                keyGen.generateKey()
            }

            "RSA" -> {
                val keyPairGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
                keyPairGen.initialize(spec)
                keyPairGen.generateKeyPair().private
            }

            else -> null
        }

    /**
     * Determines the size of the given cryptographic key in bits.
     *
     * This function calculates the key size differently based on the type of key:
     * - For RSA keys, it returns the bit length of the modulus.
     * - For symmetric keys (like AES), it returns the length of the encoded key in bits.
     * - For unsupported key types, it returns 0.
     *
     * @param key The [Key] object to measure.
     * @return The size of the key in bits, or 0 if the key type is not supported.
     */
    private fun getKeySize(key: Key): Int =
        when (key) {
            is RSAKey -> key.modulus.bitLength()
            is SecretKey -> key.encoded.size * 8
            else -> 0
        }

    /**
     * Checks for potential misuse of initialization vectors (IVs) in cryptographic operations.
     *
     * This method analyzes the application's code to identify common patterns that might
     * indicate improper handling of initialization vectors. It checks for:
     * 1. Hardcoded IVs
     * 2. Potential IV reuse
     * 3. Insufficient randomness in IV generation
     * 4. Improper IV length
     *
     * The analysis is performed by examining the bytecode of the application's classes
     * and methods for specific patterns that might indicate these issues.
     *
     * Limitations:
     * - This is a static analysis and may produce false positives or miss some runtime behaviors.
     * - The method relies on string matching in method bodies, which may not catch all cases
     *   or may incorrectly flag some legitimate uses.
     * - Obfuscated code may hinder the effectiveness of this analysis.
     *
     * @return A list of [SecurityIssue]s related to potential misuse of initialization vectors.
     *         If the list is empty, no obvious misuse was detected.
     */
    private fun checkInitializationVectors(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        val packageName = context.packageName
        val apkFile = File(context.packageCodePath)

        try {
            DexFile(apkFile).entries().toList().forEach { className ->
                if (className.startsWith(packageName)) {
                    val clazz = Class.forName(className)
                    clazz.declaredMethods.forEach { method ->
                        val body = method.toGenericString()

                        checkForHardcodedIVs(body, clazz, method, issues)
                        checkForIVReuse(body, clazz, method, issues)
                        checkForInsufficientRandomness(body, clazz, method, issues)
                        checkForImproperIVLength(body, clazz, method, issues)
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(
                SecurityIssue(
                    severity = Severity.LOW,
                    description = "Unable to analyze initialization vector usage: ${e.message}",
                    recommendation = "Manually review the code for proper IV handling in cryptographic operations.",
                ),
            )
        }

        return issues
    }

    /**
     * Checks for potential use of hardcoded initialization vectors.
     *
     * @param body The method body to analyze.
     * @param clazz The class containing the method.
     * @param method The method being analyzed.
     * @param issues The list to add any detected issues to.
     */
    private fun checkForHardcodedIVs(
        body: String,
        clazz: Class<*>,
        method: Method,
        issues: MutableList<SecurityIssue>,
    ) {
        if (body.contains("IvParameterSpec(") && body.contains("byte[]")) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Potential use of hardcoded IV detected in ${clazz.simpleName}.${method.name}",
                    recommendation = "Generate a unique IV for each encryption operation instead of using hardcoded values.",
                ),
            )
        }
    }

    /**
     * Checks for potential reuse of initialization vectors.
     *
     * @param body The method body to analyze.
     * @param clazz The class containing the method.
     * @param method The method being analyzed.
     * @param issues The list to add any detected issues to.
     */
    private fun checkForIVReuse(
        body: String,
        clazz: Class<*>,
        method: Method,
        issues: MutableList<SecurityIssue>,
    ) {
        if (body.contains("Cipher.init(") && !body.contains("IvParameterSpec(") && !body.contains("GCMParameterSpec(")) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Potential IV reuse detected in ${clazz.simpleName}.${method.name}",
                    recommendation = "Ensure a new IV is generated for each encryption operation.",
                ),
            )
        }
    }

    /**
     * Checks for potential insufficient randomness in IV generation.
     *
     * @param body The method body to analyze.
     * @param clazz The class containing the method.
     * @param method The method being analyzed.
     * @param issues The list to add any detected issues to.
     */
    private fun checkForInsufficientRandomness(
        body: String,
        clazz: Class<*>,
        method: Method,
        issues: MutableList<SecurityIssue>,
    ) {
        if (body.contains("SecureRandom(") && body.contains("setSeed(")) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Potential use of seeded SecureRandom for IV generation in ${clazz.simpleName}.${method.name}",
                    recommendation = "Avoid seeding SecureRandom when generating IVs to ensure proper randomness.",
                ),
            )
        }
    }

    /**
     * Checks for potential use of improper IV length.
     *
     * @param body The method body to analyze.
     * @param clazz The class containing the method.
     * @param method The method being analyzed.
     * @param issues The list to add any detected issues to.
     */
    private fun checkForImproperIVLength(
        body: String,
        clazz: Class<*>,
        method: Method,
        issues: MutableList<SecurityIssue>,
    ) {
        if (body.contains("IvParameterSpec(") && body.contains(".getBytes()")) {
            issues.add(
                SecurityIssue(
                    severity = Severity.MEDIUM,
                    description = "Potential use of improper IV length in ${clazz.simpleName}.${method.name}",
                    recommendation = "Ensure the IV length matches the block size of the cipher (typically 16 bytes for AES).",
                ),
            )
        }
    }

    /**
     * Checks for potential custom cryptographic implementations.
     *
     * @return A list of [SecurityIssue]s related to custom crypto implementations.
     */
    private fun checkCustomCryptoImplementations(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()

        val providers = Security.getProviders()
        val customProviders =
            providers.filter { it.name !in listOf("AndroidOpenSSL", "AndroidKeyStore") }

        if (customProviders.isNotEmpty()) {
            issues.add(
                SecurityIssue(
                    severity = Severity.HIGH,
                    description = "Custom cryptographic providers detected: ${customProviders.joinToString { it.name }}",
                    recommendation = "Avoid using custom cryptographic implementations. Rely on well-vetted standard implementations.",
                ),
            )
        }
        return issues
    }
}
