plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    namespace = "com.apasa"
    compileSdk = 35
    ndkVersion = "26.3.11579264"
    defaultConfig {
        applicationId = "com.apasa"
        minSdk = 26
        targetSdk = 35
        versionCode = 11
        versionName = "0.3.0"
        // pushir: apps signed by the same key share one connection.
        manifestPlaceholders["pushirGroup"] = "center.cxn"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

// libapasa.so from apasa-jni, cross-compiled by cargo (NDK, rustup Android targets).
cargo {
    module = "../.."
    libname = "apasa"
    targets = listOf("arm64", "x86_64")
    profile = "release"
    extraCargoBuildArguments = listOf("--package", "apasa-jni", "--locked")
}

tasks.matching { it.name.matches(Regex("merge[A-Za-z]+JniLibFolders")) }.configureEach {
    dependsOn("cargoBuild")
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.yubico.yubikit:android:2.7.0")
    implementation("com.yubico.yubikit:yubiotp:2.7.0")
    implementation(project(":pairir"))
    implementation(project(":pushir"))
}
