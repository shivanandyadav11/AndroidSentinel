package com.androidacestudio.sentinelarmor

import android.content.Context

object SentinelArmorFactory {
    fun create(context: Context): AndroidSentinel {
        return AndroidSentinelImpl(context)
    }
}