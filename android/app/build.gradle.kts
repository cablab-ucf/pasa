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
        versionCode = 19
        versionName = "0.4.7"
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
//
// -Ppasa.fast=true, to try a change and never for a release: phones' ABI
// alone and no link-time optimisation, so a change to the Rust costs seconds
// where the release's whole-program pass costs minutes.
val fast = providers.gradleProperty("pasa.fast").isPresent
val cargoBuild by tasks.registering(Exec::class) {
    workingDir = rootDir.parentFile
    val abis = if (fast) listOf("arm64-v8a") else listOf("arm64-v8a", "x86_64")
    commandLine(
        listOf("cargo", "ndk") + abis.flatMap { listOf("-t", it) } + listOf(
            "--platform", "26", "-o", file("src/main/jniLibs").path,
            "build", "--release", "--locked", "--package", "apasa-jni",
        ),
    )
    if (fast) {
        environment("CARGO_PROFILE_RELEASE_LTO", "false")
        environment("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16")
    }
    // CI says so when a cache gave the library back for these very Rust
    // sources: then there is nothing to build.
    val cached = System.getenv("PASA_SO") == "cached"
    onlyIf { !cached }
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
