package com.androidacestudio.sentinelarmor

import android.content.Context

internal class DeepLinkValidationCheck(private val context: Context): SecurityCheck {
    override fun check(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        // TODO - Update this class
        return issues
    }
}