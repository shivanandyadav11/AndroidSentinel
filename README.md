# AndroidSentinel

AndroidSentinel is a comprehensive security analysis SDK for Android applications. It provides developers with powerful tools to identify and address potential security vulnerabilities, ensuring robust protection for both the app and its users.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Security Checks](#security-checks)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Comprehensive Security Analysis**: Performs 18 distinct security checks covering a wide range of potential vulnerabilities.
- **Easy Integration**: Simple to integrate into existing Android projects with minimal setup.
- **Customizable**: Flexible configuration options to tailor security checks to your specific needs.
- **Detailed Reporting**: Provides actionable insights with severity levels and recommendations for each identified issue.
- **Lightweight**: Designed for minimal impact on app performance and size.

## Installation

Add the AndroidSentinel dependency to your project using one of the following methods:

### Groovy (build.gradle)

```groovy
dependencies {
    implementation 'com.example.androidsentinel:sentinelarmor:1.1.2' // Use Latest Version
}
```

### Kotlin DSL (build.gradle.kts)

```kotlin
dependencies {
    implementation("com.example.androidsentinel:sentinelarmor:1.1.2") // Use Latest Version
}
```

Make sure you have the appropriate repository added to your project's `settings.gradle` (Groovy) or `settings.gradle.kts` (Kotlin DSL) file:

### Groovy (settings.gradle)

```groovy
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}
```

### Kotlin DSL (settings.gradle.kts)

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

After adding the dependency, sync your project with the gradle files to download the AndroidSentinel SDK.

## Usage

1. Initialize AndroidSentinel in your application:

```kotlin
val androidSentinel = SentinelArmorFactory.create(context)
```

2. Run the security analysis:

```kotlin
val securityIssues = androidSentinel.analyzeSecurityFlaws()
```

3. Process the results:

```kotlin
securityIssues.forEach { issue ->
    SecurityLogger.logIssue(issue)
    // Handle or display the security issue as needed
}
```
4. Open LogCat and filter with Security Issue to see logs.

## Security Checks

AndroidSentinel performs the following security checks:

1. **Permissions**: Analyzes potentially sensitive permission usage.
2. **Root Detection**: Checks for indicators of a rooted device.
3. **Data Encryption**: Verifies if device encryption is enabled.
4. **ADB Debugging**: Detects if ADB debugging is active.
5. **Backup Allowed**: Checks if the app allows backups.
6. **Screen Lock Protection**: Verifies if a secure screen lock is set.
7. **Insecure Data Storage**: Looks for sensitive data in SharedPreferences.
8. **Weak Cryptography**: Checks for the use of weak cryptographic algorithms.
9. **Clipboard Vulnerability**: Warns about potential clipboard vulnerabilities.
10. **Broadcast Receivers**: Analyzes the security of broadcast receivers.
11. **WebView Security**: Checks WebView configurations for security best practices.
12. **Content Provider Exposure**: Examines content provider security.
13. **Network Security Config**: Verifies proper network security configuration.
14. **Firebase Security Rules**: Checks Firebase security if used.
15. **SQL Injection Vulnerability**: Analyzes for potential SQL injection risks.
16. **JavaScript Enabled**: Checks JavaScript settings in WebViews.
17. **Tapjacking**: Verifies protection against tapjacking attacks.
18. **Deep Link Validation**: Ensures proper validation of deep links.

## Architecture

AndroidSentinel follows SOLID principles and is designed with modularity in mind:

- `AndroidSentinel`: Main interface defining the SDK's public API.
- `AndroidSentinelImpl`: Internal implementation of the AndroidSentinel interface.
- `SentinelArmorFactory`: Factory for creating AndroidSentinel instances.
- `SecurityCheck`: Interface for individual security checks.
- `SecurityIssue`: Data class representing identified security issues.
- Individual check classes: Implement specific security checks.

This modular architecture allows for easy extension and customization of security checks.

## Contributing

We welcome contributions to AndroidSentinel! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and write tests if applicable.
4. Submit a pull request with a clear description of your changes.

Please ensure your code adheres to the project's coding standards and passes all existing tests.

## License

AndroidSentinel is released under the [MIT License](LICENSE).

---

For more information, please [open an issue](https://github.com/shivanandyadav11/AndroidSentinel/issues) or contact the maintainers.
