import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.roborazzi)
}

// Where the Zray-Core workspace lives. `local.properties: zray.core.dir=...`
// overrides it; the default is the parent directory, which is where this
// repository sits during development.
val localProps = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}
val zrayCoreDir: File = file(localProps.getProperty("zray.core.dir") ?: "${rootDir}/..")
val jniOut = layout.projectDirectory.dir("src/main/jniLibs")

// Release signing comes from keystore.properties (never committed). Without
// it, release builds are signed with the debug key so they stay installable
// for testing — CI must provide the real key.
val keystoreProps = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

// The release workflow passes the version it is building
// (-PzeronetVersion=0.1.5). It names the app, orders updates (versionCode
// must grow for Android to install one over another) and turns on the
// in-app update check, which a local build leaves off.
val zeronetVersion: String? = providers.gradleProperty("zeronetVersion").orNull?.trim()?.removePrefix("v")?.takeIf { it.isNotEmpty() }
val zeronetVersionCode: Int = zeronetVersion
    ?.substringBefore('-')
    ?.split('.')
    ?.map { it.toIntOrNull() ?: 0 }
    ?.let { p -> (p.getOrElse(0) { 0 } * 1_000_000) + (p.getOrElse(1) { 0 } * 1_000) + p.getOrElse(2) { 0 } }
    ?.coerceAtLeast(1)
    ?: 1

android {
    namespace = "com.zeronet.mobile"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.zeronet.mobile"
        minSdk = 24
        targetSdk = 37
        versionCode = zeronetVersionCode
        versionName = zeronetVersion ?: "0.1.0"
        buildConfigField("boolean", "RELEASE_CHANNEL", (zeronetVersion != null).toString())
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = false }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    signingConfigs {
        if (keystoreProps.isNotEmpty()) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (keystoreProps.isNotEmpty()) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            freeCompilerArgs.addAll(listOf("-Xjvm-default=all"))
        }
    }

    packaging {
        // Compressed in the APK: ~40% smaller download on slow mobile links,
        // at the cost of extracting the library once at install time.
        jniLibs { useLegacyPackaging = true }
        resources { excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "DebugProbesKt.bin") }
    }

    // JVM screenshot tests (Robolectric native graphics + Roborazzi).
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all { test ->
                test.systemProperty("robolectric.graphicsMode", "NATIVE")
                test.systemProperty("robolectric.pixelCopyRenderMode", "hardware")
                test.maxHeapSize = "3g"
            }
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = false
    }
}

// Build libzray_mobile.so for every ABI from the Zray-Core workspace. Cargo's
// own incremental build keeps this cheap when nothing in Rust changed.
val skipNative = providers.gradleProperty("zray.skipNative").map { it == "true" }.getOrElse(false)
val buildZrayNative by tasks.registering(Exec::class) {
    group = "zray"
    description = "Builds libzray_mobile.so for arm64-v8a, armeabi-v7a and x86_64 with cargo-ndk."
    val script = File(zrayCoreDir, "crates/zray-mobile/build-android.sh")
    val enabled = script.exists() && !skipNative
    onlyIf { enabled }
    workingDir = zrayCoreDir
    commandLine("bash", script.absolutePath, jniOut.asFile.absolutePath)
    inputs.dir(File(zrayCoreDir, "crates")).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(File(zrayCoreDir, "Cargo.toml"))
    outputs.dir(jniOut)
}
tasks.named("preBuild") { dependsOn(buildZrayNative) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.animation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.graphics.shapes)
    implementation(libs.androidx.profileinstaller)
    implementation(libs.haze)
    implementation(libs.haze.blur)
    implementation(libs.zxing.core)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.kotlinx.coroutines.android)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(libs.roborazzi.junit.rule)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
}
