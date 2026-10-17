plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "org.connecttag.libs.kotlin"
version = "1.0.5"

kotlin {
    jvmToolchain(21)
    androidTarget {
        publishLibraryVariants("release")
    }
    jvm()

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

android {
    namespace = "org.connecttag.core.crypto"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
                name.set("ConnectTag Crypto Suite")
                description.set("Kotlin Multiplatform cryptography primitives, AES, RSA, HMAC, and Base64 utilities")
                url.set("https://github.com/connecttag/crypto-suite")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("connecttagye")
                        name.set("Connect Tag")
                        email.set("connecttagye@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/connecttag/crypto-suite.git")
                    developerConnection.set("scm:git:ssh://git@github.com:connecttag/crypto-suite.git")
                    url.set("https://github.com/connecttag/crypto-suite/tree/main")
                }
            }
        }
    }
}
