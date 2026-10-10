package io.github.guidin9.warpshot

import android.content.ClipboardManager
import android.content.Intent
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Bundle
import android.text.format.Formatter
import android.util.Size
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.DrawableRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.warpshot_ffi.DeviceEntry

/** What the share card shows about the shared items. */
data class SharePreview(
    @param:DrawableRes val icon: Int,
    val title: String,
    val detail: String = "",
    val thumb: ImageBitmap? = null,
    /** A text share: [title] is the text itself. */
    val text: Boolean = false,
)

sealed interface ShareStage {
    data object Preparing : ShareStage

    /** Several PCs are paired: waiting for the user to pick one and press Send. */
    data object Choose : ShareStage
    data class Sending(val id: Long) : ShareStage

    /** [ok]: true sent, false failed, null neither (cancelled). */
    data class Ended(val ok: Boolean?, val message: String, val openApp: Boolean = false) : ShareStage
}

class ShareActions(
    val send: () -> Unit = {},
    val cancel: () -> Unit = {},
    val background: () -> Unit = {},
    val close: () -> Unit = {},
    val openApp: () -> Unit = {},
    val selectTarget: (String) -> Unit = {},
)

/**
 * Share target: copies the shared items into app storage and hands them to
 * [TransferService], showing a bottom sheet with a preview and the send's
 * progress. Leaving the sheet does not stop the send; the ongoing
 * notification keeps showing it with Cancel.
 */
open class ShareActivity : ComponentActivity() {
    /** [ClipboardActivity]: send what is on the clipboard instead of a share intent. */
    protected open val fromClipboard = false
    private var clipRead = false

    private var stage by mutableStateOf<ShareStage>(ShareStage.Preparing)
    private var preview by mutableStateOf<SharePreview?>(null)
    private var pcs by mutableStateOf<List<DeviceEntry>>(emptyList())
    private var target by mutableStateOf<String?>(null)
    private var closing by mutableStateOf(false)
    private var preparing: Job? = null
    private var chosen: CompletableDeferred<Unit>? = null

    /** Copies not handed to the service yet; deleted if the sheet goes away first. */
    @Volatile
    private var copies: List<String> = emptyList()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Configuration changes don't recreate this activity (manifest); a restore
        // after the process was killed has nothing left to show.
        if (savedInstanceState != null) {
            finish()
            return
        }
        setContent {
            WarpTheme {
                val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
                LaunchedEffect(closing) {
                    if (closing) {
                        sheet.hide()
                        finish()
                    }
                }
                val all by Transfers.state.collectAsState()
                ModalBottomSheet(onDismissRequest = { dismissed() }, sheetState = sheet) {
                    if (fromClipboard) {
                        // Android lets an app read the clipboard only while one of its windows has focus.
                        val focused = LocalWindowInfo.current.isWindowFocused
                        LaunchedEffect(focused) {
                            if (focused && !clipRead) {
                                clipRead = true
                                readClipboard()
                            }
                        }
                    }
                    ShareSheet(
                        stage = stage,
                        preview = preview,
                        pcs = pcs,
                        target = target,
                        transfer = (stage as? ShareStage.Sending)?.let { all[it.id] },
                        actions = ShareActions(
                            send = { chosen?.complete(Unit) },
                            cancel = { cancel() },
                            background = { closing = true },
                            close = { closing = true },
                            openApp = {
                                // Its own task, not the sharing app's.
                                startActivity(
                                    Intent(this@ShareActivity, MainActivity::class.java)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                )
                                finish()
                            },
                            selectTarget = {
                                target = it
                                Core.setTarget(this@ShareActivity, it)
                            },
                        ),
                    )
                }
            }
        }
        if (!fromClipboard) start(intent)
    }

    /** Text, or the first URI (e.g. a copied image), as if it had been shared. */
    private fun readClipboard() {
        val clip = runCatching { getSystemService(ClipboardManager::class.java)?.primaryClip }.getOrNull()
        val item = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)
        val uri = item?.uri
        val text = if (uri == null) item?.coerceToText(this)?.toString()?.takeIf { it.isNotEmpty() } else null
        when {
            uri != null -> start(Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, uri))
            text != null -> start(Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_TEXT, text))
            else -> stage = ShareStage.Ended(false, getString(R.string.clipboard_nothing))
        }
    }

    /** A new share while this one is still on screen (singleTop or reused task). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        start(intent)
    }

    override fun onStart() {
        super.onStart()
        (stage as? ShareStage.Sending)?.let { Transfers.watched += it.id }
    }

    override fun onStop() {
        // Not on screen any more: the service reports the result as a notification.
        (stage as? ShareStage.Sending)?.let { Transfers.watched -= it.id }
        super.onStop()
    }

    override fun onDestroy() {
        preparing?.cancel()
        Outgoing.delete(this, copies)
        super.onDestroy()
    }

    private fun start(intent: Intent) {
        (stage as? ShareStage.Sending)?.let { Transfers.watched -= it.id }
        preparing?.cancel()
        Outgoing.delete(this, copies)
        copies = emptyList()
        stage = ShareStage.Preparing
        preview = null
        preparing = lifecycleScope.launch { prepareAndSend(intent) }
    }

    /** Swiped away, tapped outside or Back: a running send continues in the background. */
    private fun dismissed() {
        if (stage !is ShareStage.Sending) preparing?.cancel()
        finish()
    }

    private fun cancel() {
        val s = stage
        if (s is ShareStage.Sending) {
            TransferService.cancel(this, s.id) // the sheet closes when the cancel lands
        } else {
            preparing?.cancel() // nothing was sent; onDestroy deletes the copies
            closing = true
        }
    }

    private suspend fun prepareAndSend(intent: Intent) {
        val core = withContext(Dispatchers.IO) { Core.get(this@ShareActivity) }
        val list = core?.let { c -> runCatching { c.devices() }.getOrNull() }.orEmpty().filter { !it.me }
        if (list.isEmpty()) {
            stage = ShareStage.Ended(false, getString(R.string.pair_first_open), openApp = true)
            return
        }
        pcs = list
        // A share through a PC's sharing shortcut goes straight to that PC.
        val shortcut = Shortcuts.target(intent)?.takeIf { id -> list.any { it.id == id } }
        target = shortcut ?: Core.target(this, list)?.id
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)
        val uris = uris(intent)
        var label = ""
        val files = mutableListOf<File>()
        when {
            uris.isNotEmpty() -> {
                preview = withContext(Dispatchers.IO) { describe(uris) }
                withContext(Dispatchers.IO) {
                    for (u in uris) {
                        val f = Outgoing.copy(this@ShareActivity, u) ?: continue
                        files += f
                        copies = files.map { it.path }
                    }
                }
                if (files.isEmpty()) {
                    stage = ShareStage.Ended(false, getString(R.string.cant_read_shared))
                    return
                }
                label = Outgoing.label(files)
            }
            !text.isNullOrEmpty() -> preview = SharePreview(R.drawable.ic_notes, text, text = true)
            else -> {
                stage = ShareStage.Ended(false, getString(R.string.nothing_to_send))
                return
            }
        }
        if (list.size > 1 && shortcut == null) {
            stage = ShareStage.Choose
            CompletableDeferred<Unit>().also { chosen = it }.await()
        }
        val pc = list.firstOrNull { it.id == target } ?: list.first()
        val id = Transfers.newId()
        val paths = files.map { it.path }
        if (!handOver(id, pc, label, if (files.isEmpty()) text else null, paths)) return
        val end = Transfers.state.first { it[id]?.outcome != null }[id]?.outcome
        when (end) {
            Outcome.Done -> {
                stage = ShareStage.Ended(true, getString(R.string.sent_to, pc.name))
                delay(1200)
                closing = true
            }
            Outcome.Cancelled -> {
                stage = ShareStage.Ended(null, getString(R.string.cancelled))
                delay(900)
                closing = true
            }
            is Outcome.Failed -> stage = ShareStage.Ended(false, getString(R.string.not_sent_reason, pc.name, end.message))
            null -> {}
        }
    }

    /** Starts the send in [TransferService]; false (and a message) if Android refused the service. */
    private fun handOver(id: Long, pc: DeviceEntry, label: String, text: String?, paths: List<String>): Boolean {
        Transfers.watched += id
        return try {
            TransferService.send(this, id, pc.id, pc.name, label, text, paths)
            copies = emptyList() // the service owns them now
            stage = ShareStage.Sending(id)
            true
        } catch (_: Exception) {
            Transfers.watched -= id
            Transfers.finish(id, Outcome.Failed(getString(R.string.start_not_allowed)))
            stage = ShareStage.Ended(false, getString(R.string.start_failed))
            false
        }
    }

    /** Name, size and a thumbnail of the shared items, for the sheet. */
    private fun describe(uris: List<Uri>): SharePreview {
        val items = uris.map { Outgoing.describe(this, it) }
        val visual = uris.all { u ->
            val mime = runCatching { contentResolver.getType(u) }.getOrNull().orEmpty()
            mime.startsWith("image/") || mime.startsWith("video/")
        }
        val sizes = items.mapNotNull { it.second }
        val detail = if (sizes.size == items.size) Formatter.formatShortFileSize(this, sizes.sum()) else ""
        val thumb = thumbnail(uris.first())
        return if (uris.size == 1) {
            SharePreview(if (visual) R.drawable.ic_image else R.drawable.ic_file, items.first().first, detail, thumb)
        } else {
            SharePreview(
                if (visual) R.drawable.ic_photos else R.drawable.ic_file,
                resources.getQuantityString(R.plurals.items, uris.size, uris.size),
                detail,
                thumb,
            )
        }
    }

    private fun thumbnail(uri: Uri): ImageBitmap? {
        runCatching { return contentResolver.loadThumbnail(uri, Size(320, 320), null).asImageBitmap() }
        val mime = runCatching { contentResolver.getType(uri) }.getOrNull().orEmpty()
        if (!mime.startsWith("image/")) return null
        return runCatching {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(contentResolver, uri)) { d, info, _ ->
                val scale = maxOf(1, minOf(info.size.width, info.size.height) / 320)
                d.setTargetSize(info.size.width / scale, info.size.height / scale)
            }.asImageBitmap()
        }.getOrNull()
    }

    private fun uris(intent: Intent): List<Uri> = when (intent.action) {
        Intent.ACTION_SEND ->
            listOfNotNull(IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java))
        Intent.ACTION_SEND_MULTIPLE ->
            IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
        else -> emptyList()
    }
}

@Composable
fun ShareSheet(
    stage: ShareStage,
    preview: SharePreview?,
    pcs: List<DeviceEntry>,
    target: String?,
    transfer: TransferState?,
    actions: ShareActions,
) {
    val ctx = LocalContext.current
    val pc = pcs.firstOrNull { it.id == target } ?: pcs.firstOrNull()
    Column(
        Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppMark(48.dp)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                // Label + name on separate lines: "Send to <name>" doesn't fit in Turkish.
                if (pc != null) {
                    Text(
                        stringResource(R.string.sending_target),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    pc?.name ?: stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (pc != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painterResource(R.drawable.ic_lock),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(12.dp),
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            stringResource(R.string.e2e),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        preview?.let { PreviewCard(it) }

        if (stage == ShareStage.Choose && pcs.size > 1) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                pcs.forEach { d ->
                    FilterChip(
                        selected = d.id == pc?.id,
                        onClick = { actions.selectTarget(d.id) },
                        label = { Text(d.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        leadingIcon = {
                            Icon(painterResource(R.drawable.ic_computer), contentDescription = null, modifier = Modifier.size(18.dp))
                        },
                    )
                }
            }
        }

        when (stage) {
            ShareStage.Preparing -> Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                StatusText(stringResource(R.string.preparing))
            }
            ShareStage.Choose -> {}
            is ShareStage.Sending -> if (transfer != null) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    TransferProgress(transfer)
                    StatusText(progressLine(ctx, transfer))
                }
            }
            is ShareStage.Ended -> Row(verticalAlignment = Alignment.Top) {
                when (stage.ok) {
                    true -> Icon(
                        painterResource(R.drawable.ic_check_circle),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    false -> Icon(
                        painterResource(R.drawable.ic_error),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                    )
                    null -> {}
                }
                if (stage.ok != null) Spacer(Modifier.width(12.dp))
                Text(stage.message, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 1.dp))
            }
        }

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) {
            when (stage) {
                ShareStage.Preparing -> TextButton(onClick = actions.cancel) { Text(stringResource(R.string.cancel)) }
                ShareStage.Choose -> {
                    TextButton(onClick = actions.cancel) { Text(stringResource(R.string.cancel)) }
                    Button(onClick = actions.send) {
                        Icon(painterResource(R.drawable.ic_send), contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.send))
                    }
                }
                is ShareStage.Sending -> {
                    TextButton(onClick = actions.cancel) { Text(stringResource(R.string.cancel)) }
                    FilledTonalButton(onClick = actions.background) { Text(stringResource(R.string.continue_background)) }
                }
                is ShareStage.Ended -> if (stage.openApp) {
                    Button(onClick = actions.openApp) { Text(stringResource(R.string.open_app)) }
                } else {
                    FilledTonalButton(onClick = actions.close) { Text(stringResource(R.string.close)) }
                }
            }
        }
    }
}

@Composable
private fun StatusText(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun PreviewCard(p: SharePreview) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            if (p.thumb != null) {
                Image(
                    p.thumb,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(64.dp).clip(RoundedCornerShape(14.dp)),
                )
            } else {
                IconTile(p.icon, size = 64.dp)
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    p.title,
                    style = if (p.text) MaterialTheme.typography.bodyMedium else MaterialTheme.typography.titleSmall,
                    maxLines = if (p.text) 3 else 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (p.detail.isNotEmpty()) {
                    Text(
                        p.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
