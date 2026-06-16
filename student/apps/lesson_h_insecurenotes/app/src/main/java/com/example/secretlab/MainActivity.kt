package com.example.secretlab

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    InsecureNotesOverview()
                }
            }
        }
    }
}

@Composable
private fun InsecureNotesOverview() {
    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Insecure Notes Lab", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("This project is the source-code scanning target for lesson H01.")
            Text("Inspect SecretStore.kt, CryptoHelper.kt, and LoggingHelper.kt for common Android security mistakes.")
            Text("All values are fake lab values and are safe to share inside the classroom context.")
        }
    }
}
