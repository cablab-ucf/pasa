pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "apasa"
include(":app", ":pairir", ":pushir")
project(":pairir").projectDir = file("pairir/android/pairir")
project(":pushir").projectDir = file("pushir/android/pushir")
