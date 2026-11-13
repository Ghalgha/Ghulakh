plugins {
    id("com.android.application")
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    // Use a real JSON implementation in local JVM tests instead of Android SDK stub methods.
    testImplementation("org.json:json:20240303")
}

android {
    namespace = "org.ghulakh.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.ghulakh.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}
