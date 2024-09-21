package com.androidacestudio.sentinelarmor

import android.content.Context

/**
 * SentinelArmorFactory
 *
 * This object serves as a factory for creating instances of [AndroidSentinel].
 * It encapsulates the creation logic of the concrete implementation [AndroidSentinelImpl],
 * providing a clean and simple interface for clients to obtain an instance of
 * AndroidSentinel without needing to know about its internal implementation details.
 *
 * The factory pattern used here allows for:
 * - Separation of object creation from its use
 * - Potential future expansion to create different types of AndroidSentinel implementations
 * - Centralized point of instantiation, making it easier to modify or extend creation logic
 *
 * Key features:
 * - Singleton object for global access
 * - Simple interface for creating AndroidSentinel instances
 * - Encapsulates the complexity of AndroidSentinel instantiation
 *
 * Usage:
 * This factory is typically used at the start of the security analysis process
 * to obtain an instance of AndroidSentinel. It should be called from the client code
 * that intends to perform security analysis on an Android application.
 *
 * Example usage:
 * ```
 * val context: Context = // obtain context
 * val androidSentinel: AndroidSentinel = SentinelArmorFactory.create(context)
 * val securityIssues = androidSentinel.analyzeSecurityFlaws()
 * ```
 *
 * Note: While currently this factory only creates instances of AndroidSentinelImpl,
 * it can be extended in the future to support creating different implementations
 * of AndroidSentinel based on various parameters or configurations.
 *
 * @see AndroidSentinel
 * @see AndroidSentinelImpl
 */
object SentinelArmorFactory {
    /**
     * Creates and returns an instance of [AndroidSentinel].
     *
     * This function instantiates a concrete implementation of AndroidSentinel
     * (currently [AndroidSentinelImpl]) and returns it as an AndroidSentinel interface.
     * This approach allows the factory to change the returned implementation in the future
     * without affecting the client code.
     *
     * @param context The Android application context. This is required by the
     *                AndroidSentinel implementation to access application-specific
     *                resources and information necessary for security analysis.
     *
     * @return An instance of [AndroidSentinel], which can be used to perform
     *         security analysis on the Android application.
     *
     * Note: The returned object is of type AndroidSentinel (interface) rather than
     * the concrete AndroidSentinelImpl. This is in line with the programming to an
     * interface principle, allowing for better flexibility and potential future changes.
     *
     * @see AndroidSentinel
     * @see Context
     */
    fun create(context: Context): AndroidSentinel = AndroidSentinelImpl(context)
}
