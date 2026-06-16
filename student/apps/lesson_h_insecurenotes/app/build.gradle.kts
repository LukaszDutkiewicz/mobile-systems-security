plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

import java.io.File
import java.util.Properties
import javax.xml.parsers.DocumentBuilderFactory
import org.gradle.api.tasks.testing.Test

val localProps = Properties().apply {
    val localPropsFile = rootProject.file("local.properties")
    if (localPropsFile.exists()) {
        localPropsFile.inputStream().use { load(it) }
    }
}

android {
    namespace = "com.example.secretlab.insecurenotes"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.secretlab.insecurenotes"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        buildConfigField(
            "String",
            "MAP_API_KEY_B64",
            "\"${localProps.getProperty("map_api_key_b64", "")}\"",
        )
        buildConfigField(
            "String",
            "TASK4_SECRET_B64",
            "\"${localProps.getProperty("task4_secret_b64", "")}\"",
        )

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        externalNativeBuild {
            cmake {
                cppFlags += ""
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.02.00")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("io.coil-kt:coil-compose:2.7.0")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    testImplementation("junit:junit:4.13.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// Prints deterministic "evidence" lines that students can paste into the Colab notebook.
// Usage (from project root): `./gradlew :app:bsmEvidence`
tasks.register("bsmEvidence") {
    group = "verification"
    description = "Prints one-line evidence strings for BSM L05E tasks (E02/E03/E04)."
    dependsOn("testDebugUnitTest")

    doLast {
        val resultsDir = File(buildDir, "test-results/testDebugUnitTest")
        val xmlFiles = resultsDir.listFiles { f -> f.isFile && f.name.startsWith("TEST-") && f.name.endsWith(".xml") }
            ?.sortedBy { it.name }
            ?: emptyList()

        fun missing(taskId: String, reason: String) {
            println("$taskId|ok=NO|reason=$reason")
        }

        if (xmlFiles.isEmpty()) {
            missing("E04", "MISSING_TEST_RESULTS")
            return@doLast
        }

        fun parseSuite(file: File): org.w3c.dom.Element? {
            val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
            val root = doc.documentElement
            return if (root != null && root.tagName == "testsuite") root else null
        }

        fun suiteAttrInt(suite: org.w3c.dom.Element, name: String): Int =
            suite.getAttribute(name).ifBlank { "0" }.toInt()

        fun suiteName(suite: org.w3c.dom.Element): String = suite.getAttribute("name").orEmpty()

        fun caseStatus(suite: org.w3c.dom.Element, method: String): String {
            val nodes = suite.getElementsByTagName("testcase")
            for (i in 0 until nodes.length) {
                val n = nodes.item(i)
                if (n !is org.w3c.dom.Element) continue
                if (n.getAttribute("name") != method) continue
                val hasFailure = n.getElementsByTagName("failure").length > 0
                val hasError = n.getElementsByTagName("error").length > 0
                return if (hasFailure || hasError) "FAIL" else "PASS"
            }
            return "MISSING"
        }

        fun evidenceFor(taskId: String, fqcn: String, required: List<String>, code: String? = null): String {
            val suite = xmlFiles.asSequence()
                .mapNotNull(::parseSuite)
                .firstOrNull { suiteName(it) == fqcn }
                ?: return ""

            val tests = suiteAttrInt(suite, "tests")
            val failures = suiteAttrInt(suite, "failures")
            val errors = suiteAttrInt(suite, "errors")
            val skipped = suiteAttrInt(suite, "skipped")

            val statuses = required.joinToString(",") { "${it}=${caseStatus(suite, it)}" }
            val requiredOk = required.all { caseStatus(suite, it) == "PASS" }
            val ok = requiredOk && failures == 0 && errors == 0
            return if (ok && code != null) code else ""
        }

        evidenceFor(
            taskId = "G02",
            fqcn = "com.example.secretlab.lab.TaskCompletionStudentTest",
            required = listOf(
                "task2CodeAppearsOnlyWhenProvenanceChecksPass",
            ),
            code = "K2Q7M",
        ).takeIf { it.isNotBlank() }?.let(::println)
        evidenceFor(
            taskId = "G03",
            fqcn = "com.example.secretlab.lab.TaskCompletionStudentTest",
            required = listOf(
                "task3CodeAppearsOnlyWhenIntegrityVerdictAndBindingAreReady",
            ),
            code = "I3B9T",
        ).takeIf { it.isNotBlank() }?.let(::println)
    }
}

// Ensure `:app:bsmEvidence` always prints evidence lines even when tests fail.
// It is a student workflow helper, not a CI gate.
tasks.matching { it.name == "testDebugUnitTest" }.configureEach {
    (this as? Test)?.let { t ->
        if (gradle.startParameter.taskNames.any { it.endsWith("bsmEvidence") }) {
            t.ignoreFailures = true
        }
    }
}
