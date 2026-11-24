plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "ae.raqeeb.app"
    compileSdk = 34
    defaultConfig {
        applicationId = "ae.raqeeb.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "2.0"
        // Laptop running the MIRA server on the same Wi-Fi. Change before building, or edit in the app.
        buildConfigField("String", "SERVER", "\"http://192.168.1.10:8000\"")
        // Optional: pin the protection-package public key (GET /api/protection/public-key). Empty = pin on first sync.
        buildConfigField("String", "PROTECTION_KEY", "\"${project.findProperty("raqeebProtectionKey") ?: ""}\"")
    }
    // Release signing (APK and AAB): put these in ~/.gradle/gradle.properties, never in the repository.
    signingConfigs {
        create("release") {
            (project.findProperty("raqeebKeystore") as String?)?.let { storeFile = file(it) }
            storePassword = project.findProperty("raqeebKeystorePassword") as String?
            keyAlias = project.findProperty("raqeebKeyAlias") as String?
            keyPassword = project.findProperty("raqeebKeyPassword") as String?
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            if (project.hasProperty("raqeebKeystore")) signingConfig = signingConfigs.getByName("release")
        }
    }
    buildFeatures { buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
}
