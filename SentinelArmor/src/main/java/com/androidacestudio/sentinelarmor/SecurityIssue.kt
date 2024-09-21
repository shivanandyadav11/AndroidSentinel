package com.androidacestudio.sentinelarmor

data class SecurityIssue(
    val severity: Severity,
    val description: String,
    val recommendation: String,
)

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
}
