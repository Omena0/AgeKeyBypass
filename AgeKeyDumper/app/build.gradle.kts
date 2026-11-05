plugins {
    id("com.android.application")
}

android {
    namespace = "dev.omena0.agekeydump"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.omena0.agekeydump"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
        }
    }
}

dependencies {
    implementation("androidx.credentials.providerevents:providerevents:1.0.0-beta01")
    implementation("androidx.credentials.providerevents:providerevents-play-services:1.0.0-beta01")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
