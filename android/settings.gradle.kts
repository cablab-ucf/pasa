pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "apasa"
include(":app", ":pairir", ":pushir")
project(":pairir").projectDir = file("qr") // the pairir submodule's QR codes, built by qr/
project(":pushir").projectDir = file("pushir/android/pushir") // submodule: one push connection
