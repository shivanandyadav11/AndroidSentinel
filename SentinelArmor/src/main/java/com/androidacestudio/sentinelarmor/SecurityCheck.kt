package com.androidacestudio.sentinelarmor

interface SecurityCheck {
    fun check(): List<SecurityIssue>
}
