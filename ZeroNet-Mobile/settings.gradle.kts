pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = uri("file:///home/parsa/.m2mirror")
            metadataSources {
                gradleMetadata()
                mavenPom()
                artifact()
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "ZeroNet"
include(":app")
