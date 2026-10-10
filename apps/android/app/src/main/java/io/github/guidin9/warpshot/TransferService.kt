package io.github.guidin9.warpshot

import android.Manifest
import android.app.DownloadManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Environment
import android.os.IBinder
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.text.format.Formatter
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.warpshot_ffi.OutgoingFile
import uniffi.warpshot_ffi.WarpException

/**
 * Foreground service (dataSync) for every transfer: receives what the PC woke
 * us for (architecture A3) and sends what the share sheet handed over, so a
 * long send keeps going after the share card is gone. Its notification shows
 * progress with a Cancel action (roadmap 3 + 4b).
 */
class TransferService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val active = AtomicInteger(0)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        // The ongoing notification follows the transfers, at most about once a
        // second (Android drops faster updates of one notification).
        scope.launch {
            Transfers.state.collect {
                refresh()
                delay(1000)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Notifier.channels(this)
        ServiceCompat.startForeground(
            this,
            Notifier.PROGRESS_ID,
            Notifier.ongoingNotification(this),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
        when (intent?.action) {
            ACTION_CANCEL -> {
                val id = intent.getLongExtra(EXTRA_ID, 0)
                val ids = if (id == ALL) Transfers.active().map { it.id } else listOf(id)
                ids.forEach { cancel(this, it) }
                if (active.get() == 0) stop()
            }
            ACTION_SEND -> run(intent.getLongExtra(EXTRA_ID, 0)) { id ->
                Sender.send(
                    applicationContext,
                    id,
                    intent.getStringExtra(EXTRA_TARGET).orEmpty(),
                    intent.getStringExtra(EXTRA_TEXT),
                    intent.getStringArrayExtra(EXTRA_PATHS).orEmpty().toList(),
                )
            }
            else -> {
                val env = intent?.getStringExtra(EXTRA_ENV)
                if (env == null) {
                    if (active.get() == 0) stop()
                } else {
                    run(Transfers.newId()) { id -> Receiver.handle(applicationContext, env, id) }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun run(id: Long, work: suspend (Long) -> Unit) {
        active.incrementAndGet()
        scope.launch {
            try {
                work(id)
            } finally {
                if (active.decrementAndGet() == 0) stop() else refresh()
            }
        }
    }

    /** Updates the ongoing notification; serialized with [stop] so none outlives the service. */
    @Synchronized
    private fun refresh() {
        if (active.get() > 0) Notifier.ongoing(this)
    }

    @Synchronized
    private fun stop() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val EXTRA_ENV = "env"
        private const val EXTRA_ID = "id"
        private const val EXTRA_TARGET = "target"
        private const val EXTRA_TEXT = "text"
        private const val EXTRA_PATHS = "paths"
        private const val ACTION_SEND = "io.github.guidin9.warpshot.SEND"
        private const val ACTION_CANCEL = "io.github.guidin9.warpshot.CANCEL"
        /** [EXTRA_ID] value for "cancel every running transfer". */
        const val ALL = -1L

        fun start(ctx: Context, env: String) {
            val i = Intent(ctx, TransferService::class.java).putExtra(EXTRA_ENV, env)
            try {
                ContextCompat.startForegroundService(ctx, i)
            } catch (_: Exception) {
                // Foreground start not allowed (e.g. battery-restricted app): receive
                // inline within the FCM handler's ~20 s window.
                runBlocking { withTimeoutOrNull(18_000) { Receiver.handle(ctx, env, Transfers.newId()) } }
            }
        }

        /**
         * Sends text or files (copies in app storage, deleted afterwards) from the
         * foreground. Registers the transfer at once so the caller can show it.
         */
        fun send(ctx: Context, id: Long, target: String, peer: String, label: String, text: String?, paths: List<String>) {
            Transfers.start(id, incoming = false, peer = peer, label = label)
            val i = Intent(ctx, TransferService::class.java)
                .setAction(ACTION_SEND)
                .putExtra(EXTRA_ID, id)
                .putExtra(EXTRA_TARGET, target)
                .putExtra(EXTRA_TEXT, text)
                .putExtra(EXTRA_PATHS, paths.toTypedArray())
            ContextCompat.startForegroundService(ctx, i)
        }

        /**
         * Cancels transfer [id]. Right after a send starts the core may not have
         * registered it yet, so this retries for about two seconds.
         */
        fun cancel(ctx: Context, id: Long) {
            val core = Core.get(ctx) ?: return
            CoroutineScope(Dispatchers.Default).launch {
                repeat(10) {
                    if (core.cancelTransfer(id.toULong())) return@launch
                    if (Transfers.state.value[id]?.outcome != null) return@launch
                    delay(200)
                }
            }
        }

        /** The notification's Cancel action for transfer [id] (or [ALL]). */
        fun cancelIntent(ctx: Context, id: Long): PendingIntent = PendingIntent.getForegroundService(
            ctx,
            id.toInt(),
            Intent(ctx, TransferService::class.java).setAction(ACTION_CANCEL).putExtra(EXTRA_ID, id),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}

/** Runs one send and reports its end when no screen shows it. */
object Sender {
    suspend fun send(ctx: Context, id: Long, target: String, text: String?, paths: List<String>) {
        val core = Core.get(ctx)
        val peer = Transfers.state.value[id]?.peer ?: ctx.getString(R.string.your_pc)
        val outcome = try {
            if (core == null) throw WarpException.NotPaired()
            if (text != null) {
                core.sendText(target, text, id.toULong())
            } else {
                core.sendFiles(target, paths.map { OutgoingFile(it) }, id.toULong())
            }
            Outcome.Done
        } catch (_: WarpException.Cancelled) {
            Outcome.Cancelled
        } catch (e: Exception) {
            Outcome.Failed(errorText(ctx, e))
        } finally {
            Outgoing.delete(ctx, paths)
        }
        Transfers.finish(id, outcome)
        if (id !in Transfers.watched) {
            when (outcome) {
                Outcome.Done -> Notifier.sent(ctx, peer)
                is Outcome.Failed -> Notifier.notSent(ctx, peer, outcome.message)
                Outcome.Cancelled -> {}
            }
        }
    }
}

/** Copies of shared items in app storage (`cache/outgoing/<n>/<name>`), kept only while sending. */
object Outgoing {
    private val swept = AtomicBoolean(false)

    fun dir(ctx: Context): File {
        val d = File(ctx.cacheDir, "outgoing")
        // Copies left by a process that died mid-send (killed, force-stopped) are
        // never sent: the first use in a new process, before any copy of its own, removes them.
        if (swept.compareAndSet(false, true)) d.listFiles()?.forEach { it.deleteRecursively() }
        return d
    }

    /** A shared item's display name (sanitized) and size, as far as its provider tells. */
    fun describe(ctx: Context, uri: Uri): Pair<String, Long?> {
        var name: String? = null
        var size: Long? = null
        runCatching {
            ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
                ?.use { c ->
                    if (c.moveToFirst()) {
                        name = c.getString(0)
                        if (!c.isNull(1)) size = c.getLong(1)
                    }
                }
        }
        var n = name ?: uri.lastPathSegment ?: "file"
        // The photo picker hides file names ("1000012345.jpg"): name it by when it was taken.
        Regex("""\d+(\.\w{1,8})?""").matchEntire(n)?.let { m ->
            val taken = runCatching {
                ctx.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.DATE_TAKEN), null, null, null)?.use { c ->
                    if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else null
                }
            }.getOrNull() ?: System.currentTimeMillis()
            n = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date(taken)) + m.groupValues[1]
        }
        return sanitize(n) to size
    }

    private fun sanitize(raw: String): String =
        raw.substringAfterLast('/').replace(Regex("[\\\\:*?\"<>|\\u0000-\\u001f]"), "_").take(120).ifBlank { "file" }

    /** Copies a shared item into `cache/outgoing/<n>/<name>`; null if it can't be read. Cancellable. */
    suspend fun copy(ctx: Context, uri: Uri): File? {
        val out = runCatching {
            File(dir(ctx), "${System.nanoTime()}").apply { mkdirs() }.let { File(it, describe(ctx, uri).first) }
        }.getOrNull() ?: return null
        val ok = runCatching {
            ctx.contentResolver.openInputStream(uri)?.use { input ->
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
            delete(ctx, listOf(out.path))
            return null
        }
        return out
    }

    /** "name" or "name +2": the label a send of [files] shows. */
    fun label(files: List<File>): String =
        files.firstOrNull()?.name.orEmpty() + if (files.size > 1) " +${files.size - 1}" else ""

    fun delete(ctx: Context, paths: List<String>) {
        val root = dir(ctx).canonicalFile
        for (p in paths) {
            val f = File(p).canonicalFile
            val parent = f.parentFile ?: continue
            // Only our own copies: cache/outgoing/<n>/<name>.
            if (parent.parentFile != root) continue
            f.delete()
            parent.delete() // only if empty
        }
    }
}

/** Handles one wake: receive, then hand the items to the phone (clipboard, gallery, Downloads). */
object Receiver {
    private const val KIND_TEXT = 1uL
    private const val KIND_IMAGE = 2uL

    suspend fun handle(ctx: Context, env: String, id: Long) {
        val core = Core.get(ctx) ?: return
        val inbox = File(ctx.cacheDir, "inbox").apply { mkdirs() }
        val from = runCatching { core.devices().firstOrNull { !it.me }?.name }.getOrNull()
            ?: ctx.getString(R.string.your_pc)
        Transfers.start(id, incoming = true, peer = from, label = "")
        val items = try {
            core.handleWake(env, inbox.path, id.toULong())
        } catch (e: WarpException.Rejected) {
            Transfers.finish(id, Outcome.Failed(errorText(ctx, e)))
            return // not a wake we accept (replay, stale, not a member): stay silent
        } catch (_: WarpException.Cancelled) {
            Transfers.finish(id, Outcome.Cancelled)
            return // cancelled here or on the PC: nothing to report
        } catch (e: Exception) {
            Transfers.finish(id, Outcome.Failed(errorText(ctx, e)))
            Notifier.failed(ctx, errorText(ctx, e))
            return
        }
        Transfers.finish(id, Outcome.Done)
        if (items.isEmpty()) return // e.g. a group-change wake
        val clipboard = ctx.getSystemService(ClipboardManager::class.java)
        for (item in items) {
            if (item.kind == KIND_TEXT) {
                val text = item.text ?: continue
                clipboard.setPrimaryClip(ClipData.newPlainText("Warpshot", text))
                Notifier.text(ctx, from, text)
                continue
            }
            val path = item.path ?: continue
            val file = File(path)
            val image = item.kind == KIND_IMAGE && item.mime.startsWith("image/")
            val uri = Store.save(ctx, file, item.name.ifBlank { file.name }, item.mime, image)
            file.delete()
            if (uri == null) {
                Notifier.failed(ctx, ctx.getString(R.string.couldnt_save, item.name))
                continue
            }
            if (image) clipboard.setPrimaryClip(ClipData.newUri(ctx.contentResolver, "Warpshot", uri))
            Notifier.saved(ctx, from, item.name, uri, item.mime, image)
        }
    }
}

/** "42 % · 12 MB / 250 MB · 8.1 MB/s" for a running transfer. */
fun progressLine(ctx: Context, t: TransferState): String {
    if (!t.running || t.total <= 0) {
        return if (t.incoming) ctx.getString(R.string.connecting) else ctx.getString(R.string.waiting_for, t.peer)
    }
    val parts = mutableListOf(
        ctx.getString(R.string.percent, (t.fraction * 100).toInt()),
        "${Formatter.formatShortFileSize(ctx, t.done)} / ${Formatter.formatShortFileSize(ctx, t.total)}",
    )
    if (t.bytesPerSec > 0) parts += ctx.getString(R.string.rate, Formatter.formatShortFileSize(ctx, t.bytesPerSec))
    return parts.joinToString(" · ")
}

/** Saves received files with MediaStore: images to Pictures/Warpshot, the rest to Download/Warpshot. */
object Store {
    fun save(ctx: Context, src: File, name: String, mime: String, image: Boolean): Uri? {
        val cr = ctx.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime.ifBlank { "application/octet-stream" })
            put(
                MediaStore.MediaColumns.RELATIVE_PATH,
                if (image) "${Environment.DIRECTORY_PICTURES}/Warpshot" else "${Environment.DIRECTORY_DOWNLOADS}/Warpshot",
            )
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val collection = if (image) {
            MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        } else {
            MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        }
        val uri = runCatching { cr.insert(collection, values) }.getOrNull() ?: return null
        return try {
            val out = cr.openOutputStream(uri) ?: error("no output stream")
            out.use { o -> src.inputStream().use { it.copyTo(o) } }
            cr.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
            uri
        } catch (_: Exception) {
            runCatching { cr.delete(uri, null, null) }
            null
        }
    }
}

object Notifier {
    const val PROGRESS_ID = 1
    private const val SLOW_ID = 2
    private const val CH_RECEIVED = "received"
    private const val CH_SENT = "sent"
    private const val CH_PROGRESS = "progress"
    private const val CH_CONNECTION = "connection"
    private val nextId = AtomicInteger(100)

    fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        // Re-created on every call, so a language change renames the channels too.
        nm.createNotificationChannel(
            NotificationChannel(CH_RECEIVED, ctx.getString(R.string.channel_received), NotificationManager.IMPORTANCE_DEFAULT),
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_SENT, ctx.getString(R.string.channel_sent), NotificationManager.IMPORTANCE_DEFAULT),
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_PROGRESS, ctx.getString(R.string.channel_progress), NotificationManager.IMPORTANCE_LOW),
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_CONNECTION, ctx.getString(R.string.channel_connection), NotificationManager.IMPORTANCE_DEFAULT),
        )
    }

    /** A transfer has had no direct path for a while (one notice, replaced on repeat). */
    fun slowRoute(ctx: Context) = post(
        ctx,
        NotificationCompat.Builder(ctx, CH_CONNECTION)
            .setSmallIcon(R.drawable.ic_notify)
            .setAutoCancel(true)
            .setContentTitle(ctx.getString(R.string.slow_title))
            .setContentText(ctx.getString(R.string.slow_text))
            .setStyle(NotificationCompat.BigTextStyle().bigText(ctx.getString(R.string.slow_big))),
        SLOW_ID,
    )

    /**
     * The foreground notification: one transfer with its progress and Cancel,
     * or several with their combined progress and "Cancel all".
     */
    fun ongoingNotification(ctx: Context): Notification {
        val list = Transfers.active()
        val b = NotificationCompat.Builder(ctx, CH_PROGRESS)
            .setSmallIcon(R.drawable.ic_notify)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openApp(ctx))
        val one = list.singleOrNull()
        when {
            list.isEmpty() -> b.setContentTitle(ctx.getString(R.string.connecting_pc)).setProgress(0, 0, true)
            one != null -> {
                val what = if (one.incoming) {
                    ctx.getString(R.string.receiving_from, one.peer)
                } else {
                    ctx.getString(R.string.sending_to, one.peer)
                }
                b.setContentTitle(if (one.label.isEmpty()) what else "$what: ${one.label}")
                    .setContentText(progressLine(ctx, one))
                    .setProgress(1000, (one.fraction * 1000).toInt(), !one.running || one.total <= 0)
                    .addAction(0, ctx.getString(R.string.cancel), TransferService.cancelIntent(ctx, one.id))
            }
            else -> {
                val total = list.sumOf { it.total }
                val done = list.sumOf { it.done }
                b.setContentTitle(ctx.getString(R.string.n_transfers, list.size))
                    .setContentText(
                        list.joinToString(", ") {
                            ctx.getString(if (it.incoming) R.string.from_peer else R.string.to_peer, it.peer)
                        },
                    )
                    .setProgress(1000, if (total > 0) (done * 1000 / total).toInt() else 0, total <= 0)
                    .addAction(0, ctx.getString(R.string.cancel_all), TransferService.cancelIntent(ctx, TransferService.ALL))
            }
        }
        return b.build()
    }

    /** Refreshes the foreground notification. */
    fun ongoing(ctx: Context) {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        NotificationManagerCompat.from(ctx).notify(PROGRESS_ID, ongoingNotification(ctx))
    }

    /** A send finished while no screen showed it. */
    fun sent(ctx: Context, peer: String) = post(
        ctx,
        builder(ctx, CH_SENT).setContentTitle(ctx.getString(R.string.sent_title, peer)).setContentIntent(openApp(ctx)),
    )

    fun notSent(ctx: Context, peer: String, message: String) = post(
        ctx,
        builder(ctx, CH_SENT)
            .setContentTitle(ctx.getString(R.string.not_sent_title, peer))
            .setContentText(message)
            .setContentIntent(openApp(ctx)),
    )

    fun text(ctx: Context, from: String, text: String) = post(
        ctx,
        builder(ctx)
            .setContentTitle(ctx.getString(R.string.text_from, from))
            .setContentText(ctx.getString(R.string.copied, text.take(120)))
            .setStyle(NotificationCompat.BigTextStyle().bigText(text.take(1000)))
            .setContentIntent(openApp(ctx)),
    )

    fun saved(ctx: Context, from: String, name: String, uri: Uri, mime: String, image: Boolean) {
        // Images open in the viewer; other files only reveal the Downloads list
        // (received files are never opened or run directly).
        val tap = if (image) {
            Intent(Intent.ACTION_VIEW).setDataAndType(uri, mime).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } else {
            Intent(DownloadManager.ACTION_VIEW_DOWNLOADS)
        }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(
            ctx,
            nextId.incrementAndGet(),
            tap,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val b = builder(ctx)
            .setContentTitle(ctx.getString(if (image) R.string.image_from else R.string.file_from, from))
            .setContentText(if (image) ctx.getString(R.string.image_saved) else ctx.getString(R.string.file_saved, name))
            .setContentIntent(pi)
        if (image) preview(ctx, uri)?.let { b.setLargeIcon(it).setStyle(NotificationCompat.BigPictureStyle().bigPicture(it)) }
        post(ctx, b)
    }

    fun failed(ctx: Context, message: String) = post(
        ctx,
        builder(ctx).setContentTitle(ctx.getString(R.string.receive_failed)).setContentText(message).setContentIntent(openApp(ctx)),
    )

    private fun builder(ctx: Context, channel: String = CH_RECEIVED) =
        NotificationCompat.Builder(ctx, channel).setSmallIcon(R.drawable.ic_notify).setAutoCancel(true)

    private fun openApp(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx,
        0,
        Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_IMMUTABLE,
    )

    private fun preview(ctx: Context, uri: Uri): Bitmap? = runCatching {
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(ctx.contentResolver, uri)) { d, info, _ ->
            val scale = maxOf(1, info.size.width / 720)
            d.setTargetSize(info.size.width / scale, info.size.height / scale)
        }
    }.getOrNull()

    private fun post(ctx: Context, b: NotificationCompat.Builder, id: Int = nextId.incrementAndGet()) {
        channels(ctx)
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        NotificationManagerCompat.from(ctx).notify(id, b.build())
    }
}
