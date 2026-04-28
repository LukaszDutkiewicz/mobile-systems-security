package com.example.secretlab

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.secretlab.secure.BiometricBoundSecretStore
import com.example.secretlab.secure.BiometricPromptGate
import com.example.secretlab.secure.GateToken
import com.example.secretlab.secure.InMemoryKeyProvider
import com.example.secretlab.secure.SecretBox
import com.example.secretlab.ui.theme.SecretLabTheme
import java.security.SecureRandom

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val random = SecureRandom()
        val secretBox = SecretBox(InMemoryKeyProvider(random))
        val clock: () -> Long = { System.currentTimeMillis() / 1000L }
        val store = BiometricBoundSecretStore(
            secretBox = secretBox,
            clock = clock,
            maxTokenAgeSeconds = 30,
        )

        val iv = ByteArray(SecretBox.IV_BYTES).also(random::nextBytes)
        store.setSecret(
            plaintextSecret = "otpauth://totp/demo?secret=BASE32SEED".encodeToByteArray(),
            iv = iv,
        )

        setContent {
            SecretLabTheme {
                LessonEApp(
                    activity = this,
                    store = store,
                    clock = clock,
                    biometricGate = BiometricPromptGate(clock = clock),
                )
            }
        }
    }
}

@Composable
private fun LessonEApp(
    activity: FragmentActivity,
    store: BiometricBoundSecretStore,
    clock: () -> Long,
    biometricGate: BiometricPromptGate,
) {
    var banner by remember { mutableStateOf("Goal: protect a local secret behind a local user gate (simulated).") }
    var tokenIssuedAt by remember { mutableStateOf<Long?>(null) }
    var secretPreview by remember { mutableStateOf<String?>(null) }
    var gateNowEpochSeconds by remember { mutableStateOf(clock().toString()) }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Secret Lab — Local Gate", style = MaterialTheme.typography.headlineMedium)
            Text(text = banner)

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Simulated gate", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "In the lab you’ll enforce the gate policy in code and verify it via unit tests. " +
                            "This screen simulates issuing a token after a successful local user-auth gate.",
                    )
                    OutlinedTextField(
                        value = gateNowEpochSeconds,
                        onValueChange = { },
                        label = { Text("Now (epoch seconds)") },
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = {
                        val now = clock()
                        gateNowEpochSeconds = now.toString()
                        tokenIssuedAt = now
                        banner = "Gate satisfied at t=$now. Token issued."
                    }) {
                        Text("Issue GateToken")
                    }

                    Button(onClick = {
                        if (!biometricGate.canAuthenticate(activity)) {
                            banner = "BiometricPrompt unavailable on this device/emulator."
                            return@Button
                        }
                        biometricGate.authenticate(activity) { token ->
                            if (token == null) {
                                banner = "Biometric auth failed/canceled."
                            } else {
                                tokenIssuedAt = token.issuedAtEpochSeconds
                                gateNowEpochSeconds = tokenIssuedAt.toString()
                                banner = "Biometric gate satisfied. Token issued."
                            }
                        }
                    }) {
                        Text("Verify biometrics (real prompt)")
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Reveal secret (policy protected)", style = MaterialTheme.typography.titleLarge)
                    Text("Result is intentionally shown as a short preview.")
                    Button(onClick = {
                        val token = tokenIssuedAt?.let { GateToken(issuedAtEpochSeconds = it) }
                        val revealed = store.revealSecret(token)
                        secretPreview = revealed?.decodeToString()?.take(24)
                        banner = if (revealed == null) "Access denied (gate not satisfied)." else "Access granted."
                    }) {
                        Text("Reveal")
                    }
                    Text(text = "Preview: ${secretPreview ?: "—"}")
                }
            }
        }
    }
}
