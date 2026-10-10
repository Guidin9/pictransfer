// Warpshot Android app. The Rust core (crates/ffi) is built with cargo-ndk into
// src/main/jniLibs and its UniFFI Kotlin bindings into src/main/java/uniffi
// (both generated, git-ignored): see apps/android/build-rust.ps1.
import groovy.json.JsonSlurper

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * Firebase values from app/google-services.json (git-ignored, ADR 0007), as the
 * string resources FirebaseApp reads at startup. This replaces the
 * google-services Gradle plugin, which FCM alone doesn't need. Without the
 * file the app builds and works, just without push wake-ups.
 */
fun firebaseValues(): Map<String, String> {
    val f = file("google-services.json")
    if (!f.exists()) return emptyMap()
    @Suppress("UNCHECKED_CAST")
    val json = JsonSlurper().parse(f) as Map<String, Any?>
    val project = json["project_info"] as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val client = (json["client"] as List<Map<String, Any?>>).first {
        val info = it["client_info"] as Map<String, Any?>
        (info["android_client_info"] as Map<String, Any?>)["package_name"] == "io.github.guidin9.warpshot"
    }
    @Suppress("UNCHECKED_CAST")
    val apiKey = (client["api_key"] as List<Map<String, Any?>>).first()["current_key"] as String
    return mapOf(
        "google_app_id" to ((client["client_info"] as Map<String, Any?>)["mobilesdk_app_id"] as String),
        "google_api_key" to apiKey,
        "gcm_defaultSenderId" to (project["project_number"] as String),
        "project_id" to (project["project_id"] as String),
    )
}

android {
    namespace = "io.github.guidin9.warpshot"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.guidin9.warpshot"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a") }
        firebaseValues().forEach { (k, v) -> resValue("string", k, v) }
    }

    buildTypes {
        release {
            // R8: about half the APK and less code in memory. UniFFI's JNA
            // bindings use reflection; proguard-rules.pro keeps them.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Personal builds are signed with the debug key until Faz 3 signing.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        resValues = true
    }
    packaging { jniLibs { useLegacyPackaging = false } }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // UniFFI bindings load the Rust library through JNA (Apache-2.0 / LGPL-2.1).
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    // QR scanning UI from Google Play services: no camera permission in the app.
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    // Push wake-ups (protocol §6.5): high-priority data messages only, no analytics.
    implementation("com.google.firebase:firebase-messaging:24.1.0")
}
