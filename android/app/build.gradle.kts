plugins {
    id("com.android.application") // AGP 9: Kotlin is built in
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.apasa"
    compileSdk = 37
    ndkVersion = "30.0.16248370"
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
    buildFeatures { compose = true }
}

// libapasa.so from apasa-jni, cross-compiled by cargo-ndk (ANDROID_NDK_HOME,
// rustup's Android targets) into jniLibs, which the app packs.
val cargoBuild by tasks.registering(Exec::class) {
    workingDir = rootDir.parentFile
    commandLine(
        "cargo", "ndk", "-t", "arm64-v8a", "-t", "x86_64", "--platform", "26",
        "-o", file("src/main/jniLibs").path,
        "build", "--release", "--locked", "--package", "apasa-jni",
    )
}

tasks.matching { it.name.matches(Regex("merge[A-Za-z]+JniLibFolders")) }.configureEach {
    dependsOn(cargoBuild)
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("com.yubico.yubikit:android:3.3.0")
    implementation("com.yubico.yubikit:yubiotp:3.3.0")
    implementation(project(":pairir"))
    implementation(project(":pushir"))
}
