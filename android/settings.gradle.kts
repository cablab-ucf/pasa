pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "apasa"
include(":app", ":irpair", ":irpush")
project(":irpair").projectDir = file("irpair/android/irpair") // submodule: QR codes
project(":irpush").projectDir = file("irpush/android/irpush") // submodule: one push connection
