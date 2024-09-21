package com.androidacestudio.sentinelarmor

interface AndroidSentinel {
    fun analyzeSecurityFlaws(): List<SecurityIssue>
}