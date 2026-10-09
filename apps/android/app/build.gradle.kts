// Warpshot Android app. The Rust core (crates/ffi) is built with cargo-ndk into
// src/main/jniLibs and its UniFFI Kotlin bindings into src/main/java/uniffi
// (both generated, git-ignored): see apps/android/build-rust.ps1.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
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
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Personal builds are signed with the debug key until Faz 3 signing.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }
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
}
