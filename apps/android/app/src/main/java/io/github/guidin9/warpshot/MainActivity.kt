package io.github.guidin9.warpshot

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
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
import androidx.compose.ui.res.stringResource
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
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    LaunchedEffect(Unit) { refresh() }
    // Once paired: register for push wake-ups and ask to show "received" notifications.
    LaunchedEffect(devices.any { !it.me }) {
        if (devices.none { !it.me }) return@LaunchedEffect
        Push.ensureRegistered(ctx)
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
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
                    status = ctx.getString(R.string.pair_not_code)
                    return@addOnSuccessListener
                }
                busy = true
                status = ctx.getString(R.string.pairing)
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
                        ctx.getString(R.string.paired)
                    } catch (e: Exception) {
                        ctx.getString(R.string.pairing_failed, errorText(ctx, e))
                    }
                    sas = null
                    busy = false
                    refresh()
                }
            }
            .addOnFailureListener { status = ctx.getString(R.string.scanner_unavailable, it.javaClass.simpleName) }
    }

    Column(
        Modifier.safeDrawingPadding().padding(20.dp).fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        if (pcs.isEmpty()) {
            Text(stringResource(R.string.pair_intro))
            Button(onClick = { scanAndPair() }, enabled = !busy) { Text(stringResource(R.string.scan_code)) }
        } else {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.paired_devices), style = MaterialTheme.typography.titleMedium)
                    pcs.forEach { Text("• ${it.name}") }
                }
            }
            Text(stringResource(R.string.share_hint))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text(stringResource(R.string.text_to_send)) },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = text.isNotBlank() && !busy,
                onClick = {
                    val core = Core.get(ctx) ?: return@Button
                    val target = pcs.first().id
                    busy = true
                    status = ctx.getString(R.string.sending)
                    scope.launch {
                        status = try {
                            core.sendText(target, text, Transfers.newId().toULong())
                            text = ""
                            ctx.getString(R.string.sent_to, pcs.first().name)
                        } catch (e: Exception) {
                            errorText(ctx, e)
                        }
                        busy = false
                    }
                },
            ) { Text(stringResource(R.string.send_to, pcs.first().name)) }
            TextButton(onClick = { scanAndPair() }, enabled = !busy) { Text(stringResource(R.string.pair_another)) }
        }
        Spacer(Modifier.height(8.dp))
        if (status.isNotEmpty()) Text(status)
    }

    sas?.let { q ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.confirm_pairing)) },
            text = { Text(stringResource(R.string.confirm_pairing_body, q.peer, q.sas)) },
            confirmButton = {
                TextButton(onClick = { q.answer.complete(true); sas = null }) { Text(stringResource(R.string.codes_match)) }
            },
            dismissButton = {
                TextButton(onClick = { q.answer.complete(false); sas = null }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
}
