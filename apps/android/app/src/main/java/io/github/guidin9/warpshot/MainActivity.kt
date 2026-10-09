package io.github.guidin9.warpshot

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.launch
import uniffi.warpshot_ffi.DeviceEntry
import uniffi.warpshot_ffi.PairConfirm

@Composable
fun WarpTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val dark = isSystemInDarkTheme()
    val scheme = if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
    MaterialTheme(colorScheme = scheme, content = content)
}

/** Pending SAS question from the core (asked on a Rust thread, answered in the UI). */
data class SasQuestion(val sas: String, val peer: String, val answer: CompletableFuture<Boolean>)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { WarpTheme { Surface(Modifier.fillMaxSize()) { MainScreen() } } }
    }
}

@Composable
fun MainScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf<List<DeviceEntry>>(emptyList()) }
    var status by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var sas by remember { mutableStateOf<SasQuestion?>(null) }
    var text by remember { mutableStateOf("") }
    val setSas: (SasQuestion?) -> Unit = { sas = it }

    suspend fun refresh() {
        val core = Core.get(ctx) ?: return
        runCatching { core.sync() }
        devices = runCatching { core.devices() }.getOrDefault(emptyList())
    }
    LaunchedEffect(Unit) { refresh() }
    val pcs = devices.filter { !it.me }

    fun scanAndPair() {
        val opts = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        GmsBarcodeScanning.getClient(ctx, opts).startScan()
            .addOnSuccessListener { code ->
                val raw = code.rawValue ?: return@addOnSuccessListener
                val core = Core.forQr(ctx, raw)
                if (core == null) {
                    status = "This is not a Warpshot pairing code."
                    return@addOnSuccessListener
                }
                busy = true
                status = "Pairing…"
                scope.launch {
                    val confirm = object : PairConfirm {
                        override fun confirm(sas: String, peerName: String, peerPlatform: ULong): Boolean {
                            val q = SasQuestion(sas, peerName, CompletableFuture())
                            scope.launch { setSas(q) }
                            return runCatching { q.answer.get(90, TimeUnit.SECONDS) }.getOrDefault(false)
                        }
                    }
                    status = try {
                        core.pairScan(raw, confirm)
                        "Paired."
                    } catch (e: Exception) {
                        "Pairing failed. ${errorText(e)}"
                    }
                    sas = null
                    busy = false
                    refresh()
                }
            }
            .addOnFailureListener { status = "Scanner unavailable: ${it.javaClass.simpleName}" }
    }

    Column(
        Modifier.safeDrawingPadding().padding(20.dp).fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Warpshot", style = MaterialTheme.typography.headlineMedium)
        if (pcs.isEmpty()) {
            Text("Open Warpshot settings on your PC (tray icon → Settings → Pair), then scan the QR code.")
            Button(onClick = { scanAndPair() }, enabled = !busy) { Text("Scan pairing code") }
        } else {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Paired devices", style = MaterialTheme.typography.titleMedium)
                    pcs.forEach { Text("• ${it.name}") }
                }
            }
            Text("Send a screenshot or file: open it, tap Share and choose Warpshot.")
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Text to send") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = text.isNotBlank() && !busy,
                onClick = {
                    val core = Core.get(ctx) ?: return@Button
                    val target = pcs.first().id
                    busy = true
                    status = "Sending…"
                    scope.launch {
                        status = try {
                            core.sendText(target, text)
                            text = ""
                            "Sent to ${pcs.first().name}."
                        } catch (e: Exception) {
                            errorText(e)
                        }
                        busy = false
                    }
                },
            ) { Text("Send to ${pcs.first().name}") }
            TextButton(onClick = { scanAndPair() }, enabled = !busy) { Text("Pair another PC") }
        }
        Spacer(Modifier.height(8.dp))
        if (status.isNotEmpty()) Text(status)
    }

    sas?.let { q ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Confirm pairing") },
            text = {
                Text("Pair with \"${q.peer}\"?\n\nCheck that your PC shows the same code:\n\n${q.sas}")
            },
            confirmButton = {
                TextButton(onClick = { q.answer.complete(true); sas = null }) { Text("Codes match") }
            },
            dismissButton = {
                TextButton(onClick = { q.answer.complete(false); sas = null }) { Text("Cancel") }
            },
        )
    }
}
