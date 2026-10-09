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
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.warpshot_ffi.WarpException

/**
 * Foreground service (dataSync) started from a high-priority FCM message: dials
 * the PC that woke us and receives the items (architecture A3).
 */
class TransferService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val active = AtomicInteger(0)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Notifier.channels(this)
        ServiceCompat.startForeground(
            this,
            Notifier.PROGRESS_ID,
            Notifier.progress(this),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
        val env = intent?.getStringExtra(EXTRA_ENV)
        if (env == null) {
            if (active.get() == 0) stop()
            return START_NOT_STICKY
        }
        active.incrementAndGet()
        scope.launch {
            try {
                Receiver.handle(applicationContext, env)
            } finally {
                if (active.decrementAndGet() == 0) stop()
            }
        }
        return START_NOT_STICKY
    }

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

        fun start(ctx: Context, env: String) {
            val i = Intent(ctx, TransferService::class.java).putExtra(EXTRA_ENV, env)
            try {
                ContextCompat.startForegroundService(ctx, i)
            } catch (_: Exception) {
                // Foreground start not allowed (e.g. battery-restricted app): receive
                // inline within the FCM handler's ~20 s window.
                runBlocking { withTimeoutOrNull(18_000) { Receiver.handle(ctx, env) } }
            }
        }
    }
}

/** Handles one wake: receive, then hand the items to the phone (clipboard, gallery, Downloads). */
object Receiver {
    private const val KIND_TEXT = 1uL
    private const val KIND_IMAGE = 2uL

    suspend fun handle(ctx: Context, env: String) {
        val core = Core.get(ctx) ?: return
        val inbox = File(ctx.cacheDir, "inbox").apply { mkdirs() }
        val items = try {
            core.handleWake(env, inbox.path)
        } catch (e: WarpException.Rejected) {
            return // not a wake we accept (replay, stale, not a member): stay silent
        } catch (e: Exception) {
            Notifier.failed(ctx, errorText(e))
            return
        }
        if (items.isEmpty()) return // e.g. a group-change wake
        val from = runCatching { core.devices().firstOrNull { !it.me }?.name }.getOrNull() ?: "your PC"
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
                Notifier.failed(ctx, "Couldn't save ${item.name}.")
                continue
            }
            if (image) clipboard.setPrimaryClip(ClipData.newUri(ctx.contentResolver, "Warpshot", uri))
            Notifier.saved(ctx, from, item.name, uri, item.mime, image)
        }
    }
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
    private const val CH_RECEIVED = "received"
    private const val CH_PROGRESS = "progress"
    private val nextId = AtomicInteger(100)

    fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CH_RECEIVED, "Received from your PC", NotificationManager.IMPORTANCE_DEFAULT),
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_PROGRESS, "Transfers in progress", NotificationManager.IMPORTANCE_LOW),
        )
    }

    fun progress(ctx: Context): Notification =
        NotificationCompat.Builder(ctx, CH_PROGRESS)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Receiving from your PC…")
            .setOngoing(true)
            .setSilent(true)
            .build()

    fun text(ctx: Context, from: String, text: String) = post(
        ctx,
        builder(ctx)
            .setContentTitle("Text from $from")
            .setContentText("Copied: ${text.take(120)}")
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
            .setContentTitle(if (image) "Image from $from" else "File from $from")
            .setContentText(if (image) "Copied and saved to Pictures/Warpshot" else "$name saved to Download/Warpshot")
            .setContentIntent(pi)
        if (image) preview(ctx, uri)?.let { b.setLargeIcon(it).setStyle(NotificationCompat.BigPictureStyle().bigPicture(it)) }
        post(ctx, b)
    }

    fun failed(ctx: Context, message: String) = post(
        ctx,
        builder(ctx).setContentTitle("Couldn't receive from your PC").setContentText(message).setContentIntent(openApp(ctx)),
    )

    private fun builder(ctx: Context) =
        NotificationCompat.Builder(ctx, CH_RECEIVED).setSmallIcon(R.drawable.ic_notify).setAutoCancel(true)

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

    private fun post(ctx: Context, b: NotificationCompat.Builder) {
        channels(ctx)
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        NotificationManagerCompat.from(ctx).notify(nextId.incrementAndGet(), b.build())
    }
}
