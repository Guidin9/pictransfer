package io.github.guidin9.warpshot

import android.content.Context
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * FCM entry point. A data message carries only `v` and the sealed wake envelope
 * `e` (protocol §6.5); everything else happens over the direct connection.
 */
class PushService : FirebaseMessagingService() {
    override fun onNewToken(token: String) = Push.register(applicationContext, token)

    override fun onMessageReceived(message: RemoteMessage) {
        val data = message.data
        if (data["v"] != "1") return
        val env = data["e"] ?: return
        TransferService.start(applicationContext, env)
    }
}

/** Push-token registration with the group server (§6.2). */
object Push {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Registers the current FCM token; a no-op when Firebase isn't configured. */
    fun ensureRegistered(ctx: Context) {
        val app = ctx.applicationContext
        runCatching {
            FirebaseMessaging.getInstance().token.addOnSuccessListener { register(app, it) }
        }
    }

    fun register(ctx: Context, token: String) {
        scope.launch {
            val core = Core.get(ctx) ?: return@launch
            if (!runCatching { core.isPaired() }.getOrDefault(false)) return@launch
            runCatching { core.registerPushToken(token) }
        }
    }
}
