package com.androidacestudio.sentinelarmor

import android.util.Log

object SecurityLogger {
    private const val TAG = "AndroidSentinel"

    fun logIssue(issue: SecurityIssue) {
        Log.w(
            TAG,
            "Security Issue - Severity: ${issue.severity}, Description: ${issue.description}, Recommendation: ${issue.recommendation}",
        )
    }
}
