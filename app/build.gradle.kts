plugins {
    id("com.android.application")
}

android {
    namespace = "com.scarface.stegostudio"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.scarface.stegostudio"
        minSdk = 26
        targetSdk = 36
        versionCode = 5
        versionName = "0.3.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
