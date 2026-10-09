package io.github.guidin9.warpshot

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.warpshot_ffi.OutgoingFile

/** Share target: sends shared images, files or text to the paired PC. */
class ShareActivity : ComponentActivity() {
    private var state by mutableStateOf("Preparing…")
    private var done by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WarpTheme {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                    Card(Modifier.padding(24.dp)) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Warpshot", style = MaterialTheme.typography.titleMedium)
                            Text(state)
                            if (!done) LinearProgressIndicator() else TextButton(onClick = { finish() }) { Text("Close") }
                        }
                    }
                }
            }
        }
        if (savedInstanceState == null) lifecycleScope.launch { send(intent) }
    }

    private suspend fun send(intent: Intent) {
        val core = Core.get(this)
        val pc = core?.let { c -> runCatching { c.devices() }.getOrNull()?.firstOrNull { !it.me } }
        if (core == null || pc == null) {
            finishWith("Open Warpshot and pair with your PC first.")
            return
        }
        state = "Sending to ${pc.name}…"
        try {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            val uris = uris(intent)
            if (uris.isEmpty() && !text.isNullOrEmpty()) {
                core.sendText(pc.id, text)
            } else if (uris.isNotEmpty()) {
                val files = withContext(Dispatchers.IO) { uris.mapNotNull { copyToCache(it) } }
                try {
                    core.sendFiles(pc.id, files.map { OutgoingFile(it.path) })
                } finally {
                    files.forEach { it.delete() }
                }
            } else {
                finishWith("Nothing to send.")
                return
            }
            finishWith("Sent to ${pc.name}.", auto = true)
        } catch (e: Exception) {
            finishWith(errorText(e))
        }
    }

    private suspend fun finishWith(msg: String, auto: Boolean = false) {
        state = msg
        done = true
        if (auto) {
            delay(900)
            finish()
        }
    }

    private fun uris(intent: Intent): List<Uri> = when (intent.action) {
        Intent.ACTION_SEND ->
            listOfNotNull(IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java))
        Intent.ACTION_SEND_MULTIPLE ->
            IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
        else -> emptyList()
    }

    /** Copies a shared item into app-private cache under its (sanitized) display name. */
    private fun copyToCache(uri: Uri): File? = runCatching {
        var name = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
            ?: uri.lastPathSegment ?: "file"
        name = name.substringAfterLast('/').replace(Regex("[\\\\:*?\"<>|\\u0000-\\u001f]"), "_").take(120)
        if (name.isBlank()) name = "file"
        val dir = File(cacheDir, "outgoing/${System.nanoTime()}").apply { mkdirs() }
        val out = File(dir, name)
        contentResolver.openInputStream(uri)?.use { input -> out.outputStream().use { input.copyTo(it) } }
            ?: return null
        out
    }.getOrNull()
}
