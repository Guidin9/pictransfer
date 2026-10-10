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
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Share target: copies the shared items into app storage and hands them to
 * [TransferService], then shows the send's progress. Leaving the card does not
 * stop the send; the ongoing notification keeps showing it with Cancel.
 */
class ShareActivity : ComponentActivity() {
    private var message by mutableStateOf("")
    private var transferId by mutableStateOf<Long?>(null)
    private var closable by mutableStateOf(false)
    private var preparing: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WarpTheme {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                    Card(Modifier.padding(24.dp).fillMaxWidth()) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleMedium)
                            val all by Transfers.state.collectAsState()
                            val t = transferId?.let { all[it] }
                            if (t != null && t.outcome == null) Running(t) else Text(message)
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                if (closable) {
                                    TextButton(onClick = { finish() }) { Text(stringResource(R.string.close)) }
                                } else {
                                    TextButton(onClick = { cancel() }) { Text(stringResource(R.string.cancel)) }
                                    if (t != null) TextButton(onClick = { finish() }) { Text(stringResource(R.string.continue_background)) }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (savedInstanceState == null) start(intent)
    }

    @androidx.compose.runtime.Composable
    private fun Running(t: TransferState) {
        Text(
            if (t.label.isEmpty()) {
                stringResource(R.string.sending_to, t.peer)
            } else {
                stringResource(R.string.sending_item_to, t.label, t.peer)
            },
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        if (t.running && t.total > 0) {
            LinearProgressIndicator(progress = { t.fraction }, modifier = Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        Text(progressLine(this, t), style = MaterialTheme.typography.bodySmall)
    }

    /** A new share while this one is still on screen (singleTop or reused task). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        start(intent)
    }

    override fun onStart() {
        super.onStart()
        transferId?.let { Transfers.watched += it }
    }

    override fun onStop() {
        // Not on screen any more: the service reports the result as a notification.
        transferId?.let { Transfers.watched -= it }
        super.onStop()
    }

    private fun start(intent: Intent) {
        transferId?.let { Transfers.watched -= it }
        transferId = null
        closable = false
        message = getString(R.string.preparing)
        preparing = lifecycleScope.launch { prepareAndSend(intent) }
    }

    private fun cancel() {
        val id = transferId
        if (id == null) {
            preparing?.cancel() // still copying: nothing was sent
            finish()
            return
        }
        TransferService.cancel(this, id)
    }

    private suspend fun prepareAndSend(intent: Intent) {
        val core = Core.get(this)
        val pc = core?.let { c -> runCatching { c.devices() }.getOrNull()?.firstOrNull { !it.me } }
        if (core == null || pc == null) return finishWith(getString(R.string.pair_first_open))
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)
        val uris = uris(intent)
        val id = Transfers.newId()
        when {
            uris.isNotEmpty() -> {
                val files = withContext(Dispatchers.IO) { uris.mapNotNull { copyToCache(it) } }
                if (files.isEmpty()) return finishWith(getString(R.string.cant_read_shared))
                val label = files.first().name + if (files.size > 1) " +${files.size - 1}" else ""
                if (!handOver(id, pc.id, pc.name, label, null, files.map { it.path })) return
            }
            !text.isNullOrEmpty() -> if (!handOver(id, pc.id, pc.name, "", text, emptyList())) return
            else -> return finishWith(getString(R.string.nothing_to_send))
        }
        transferId = id
        val end = Transfers.state.first { it[id]?.outcome != null }[id]?.outcome
        when (end) {
            Outcome.Done -> finishWith(getString(R.string.sent_to, pc.name), auto = true)
            Outcome.Cancelled -> finishWith(getString(R.string.cancelled), auto = true)
            is Outcome.Failed -> finishWith(end.message)
            null -> {}
        }
    }

    /** Starts the send in [TransferService]; false (and a message) if Android refused the service. */
    private suspend fun handOver(id: Long, target: String, peer: String, label: String, text: String?, paths: List<String>): Boolean {
        Transfers.watched += id
        return try {
            TransferService.send(this, id, target, peer, label, text, paths)
            true
        } catch (_: Exception) {
            Transfers.watched -= id
            Transfers.finish(id, Outcome.Failed(getString(R.string.start_not_allowed)))
            Outgoing.delete(this, paths)
            finishWith(getString(R.string.start_failed))
            false
        }
    }

    private suspend fun finishWith(msg: String, auto: Boolean = false) {
        message = msg
        closable = true
        transferId = null
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
    private suspend fun copyToCache(uri: Uri): File? {
        val out = runCatching {
            var name = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
                ?: uri.lastPathSegment ?: "file"
            name = name.substringAfterLast('/').replace(Regex("[\\\\:*?\"<>|\\u0000-\\u001f]"), "_").take(120)
            if (name.isBlank()) name = "file"
            File(Outgoing.dir(this), "${System.nanoTime()}").apply { mkdirs() }.let { File(it, name) }
        }.getOrNull() ?: return null
        val ok = runCatching {
            contentResolver.openInputStream(uri)?.use { input ->
                out.outputStream().use { o ->
                    val buf = ByteArray(256 * 1024)
                    while (true) {
                        currentCoroutineContext().ensureActive() // cancelled while preparing
                        val n = input.read(buf)
                        if (n < 0) break
                        o.write(buf, 0, n)
                    }
                }
            } != null
        }.getOrDefault(false)
        if (!ok) {
            Outgoing.delete(this, listOf(out.path))
            return null
        }
        return out
    }
}
