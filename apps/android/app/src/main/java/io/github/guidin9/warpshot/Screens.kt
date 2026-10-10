package io.github.guidin9.warpshot

import android.app.DownloadManager
import android.app.StatusBarManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon as SysIcon
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.text.format.DateUtils
import android.text.format.Formatter
import android.util.LruCache
import android.util.Size
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.warpshot_ffi.DeviceEntry
import uniffi.warpshot_ffi.HistoryEntry
import uniffi.warpshot_ffi.Presence

// ---------------------------------------------------------------- shared

/** A sub-screen: back arrow and title (no brand header), then a list. */
@Composable
fun SubScreen(
    title: String,
    onBack: () -> Unit,
    snackbar: SnackbarHostState,
    actions: @Composable RowScope.() -> Unit = {},
    content: LazyListScope.() -> Unit,
) {
    BackHandler(onBack = onBack)
    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, contentWindowInsets = WindowInsets.safeDrawing) { pad ->
        Column(Modifier.fillMaxSize().padding(top = pad.calculateTopPadding())) {
            Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.back))
                }
                Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f).padding(start = 4.dp))
                actions()
            }
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = pad.calculateBottomPadding() + 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                content = content,
            )
        }
    }
}

@Composable
fun Section(content: @Composable () -> Unit) {
    Card(
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) { content() }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
}

@Composable
private fun Muted(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = modifier)
}

// ---------------------------------------------------------------- history

object HistoryUi {
    private val thumbs = LruCache<String, ImageBitmap>(64)

    suspend fun load(ctx: Context, limit: Int): List<HistoryEntry> = withContext(Dispatchers.IO) {
        Core.get(ctx)?.let { runCatching { it.historyList(null, limit.toUInt()) }.getOrNull() }.orEmpty()
    }

    fun cached(uri: String): ImageBitmap? = thumbs.get(uri)

    suspend fun thumb(ctx: Context, uri: String): ImageBitmap? = withContext(Dispatchers.IO) {
        runCatching { ctx.contentResolver.loadThumbnail(Uri.parse(uri), Size(160, 160), null).asImageBitmap() }
            .getOrNull()?.also { thumbs.put(uri, it) }
    }

    /**
     * Tap on a row: text is copied again, a received image opens in the
     * viewer, a received file only reveals the Downloads list (received files
     * are never opened directly). Returns a message for the snackbar.
     */
    fun open(ctx: Context, e: HistoryEntry): String? {
        if (e.kind == Kind.TEXT) {
            val text = e.text ?: return null
            ctx.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("Warpshot", text))
            return ctx.getString(R.string.copied_toast)
        }
        val uri = e.uri ?: return null
        val i = if (e.kind == Kind.IMAGE) {
            Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse(uri), "image/*").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } else {
            Intent(DownloadManager.ACTION_VIEW_DOWNLOADS)
        }
        return if (runCatching { ctx.startActivity(i) }.isSuccess) null else ctx.getString(R.string.open_failed)
    }
}

@Composable
private fun Thumb(e: HistoryEntry) {
    val ctx = LocalContext.current
    val uri = e.uri?.takeIf { e.incoming && e.kind == Kind.IMAGE }
    val bmp by produceState(uri?.let { HistoryUi.cached(it) }, uri) {
        value = uri?.let { HistoryUi.cached(it) ?: HistoryUi.thumb(ctx, it) }
    }
    val b = bmp
    if (b != null) {
        Image(b, contentDescription = null, contentScale = ContentScale.Crop, modifier = Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)))
    } else {
        val icon = when (e.kind) {
            Kind.TEXT -> R.drawable.ic_notes
            Kind.IMAGE -> R.drawable.ic_image
            else -> R.drawable.ic_file
        }
        IconTile(icon, size = 44.dp)
    }
}

/** One history row: what, from/to whom, when, size; failed rows say so. */
@Composable
fun HistoryRow(e: HistoryEntry, onOpen: () -> Unit, onDelete: (() -> Unit)? = null) {
    val ctx = LocalContext.current
    val peer = e.peerName ?: stringResource(R.string.removed_device)
    val ts = e.ts.toLong()
    val flags = if (DateUtils.isToday(ts)) {
        DateUtils.FORMAT_SHOW_TIME
    } else {
        DateUtils.FORMAT_SHOW_TIME or DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH
    }
    val parts = buildList {
        if (!e.ok) add(stringResource(if (e.incoming) R.string.not_received else R.string.not_sent))
        add(stringResource(if (e.incoming) R.string.from_peer else R.string.to_peer, peer))
        add(DateUtils.formatDateTime(ctx, ts, flags))
        if (e.kind != Kind.TEXT && e.size > 0uL) add(Formatter.formatShortFileSize(ctx, e.size.toLong()))
    }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable(onClick = onOpen).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Thumb(e)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                (if (e.kind == Kind.TEXT) e.text else e.name).orEmpty(),
                style = MaterialTheme.typography.bodyLarge,
                maxLines = if (e.kind == Kind.TEXT) 2 else 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painterResource(if (e.incoming) R.drawable.ic_arrow_down else R.drawable.ic_arrow_up),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    parts.joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (e.ok) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (onDelete != null) {
            var menu by remember { mutableStateOf(false) }
            Box {
                IconButton(onClick = { menu = true }) {
                    Icon(painterResource(R.drawable.ic_more_vert), contentDescription = stringResource(R.string.more))
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(stringResource(R.string.delete)) }, onClick = {
                        menu = false
                        onDelete()
                    })
                }
            }
        }
    }
}

/** The home screen's last few rows with "See all". */
@Composable
fun RecentSection(recent: List<HistoryEntry>, onOpen: (HistoryEntry) -> Unit, onSeeAll: () -> Unit) = Section {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(stringResource(R.string.recent), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
        TextButton(onClick = onSeeAll) { Text(stringResource(R.string.see_all)) }
    }
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        recent.forEach { e -> key(e.id) { HistoryRow(e, onOpen = { onOpen(e) }) } }
    }
}

@Composable
fun ClearHistoryDialog(onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.history_clear_q)) },
        text = { Text(stringResource(R.string.history_clear_body)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.clear)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

suspend fun clearHistory(ctx: Context) {
    withContext(Dispatchers.IO) { Core.get(ctx)?.let { runCatching { it.historyClear() } } }
    HistoryLog.touch()
}

@Composable
fun HistoryScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val tick by HistoryLog.changed.collectAsState()
    var entries by remember { mutableStateOf<List<HistoryEntry>?>(null) }
    var confirm by remember { mutableStateOf(false) }
    LaunchedEffect(tick) { entries = HistoryUi.load(ctx, 200) }
    SubScreen(stringResource(R.string.menu_history), onBack, snackbar, actions = {
        if (!entries.isNullOrEmpty()) {
            TextButton(onClick = { confirm = true }) { Text(stringResource(R.string.history_clear)) }
        }
    }) {
        val list = entries
        when {
            list == null -> {}
            list.isEmpty() -> item { Muted(stringResource(R.string.history_empty), Modifier.padding(8.dp)) }
            else -> items(list, key = { it.id }) { e ->
                HistoryRow(
                    e,
                    onOpen = { HistoryUi.open(ctx, e)?.let { m -> scope.launch { snackbar.showSnackbar(m) } } },
                    onDelete = {
                        scope.launch {
                            withContext(Dispatchers.IO) { Core.get(ctx)?.let { runCatching { it.historyDelete(e.id) } } }
                            HistoryLog.touch()
                        }
                    },
                )
            }
        }
    }
    if (confirm) {
        ClearHistoryDialog(onDismiss = { confirm = false }) {
            confirm = false
            scope.launch { clearHistory(ctx) }
        }
    }
}

// ---------------------------------------------------------------- devices

/** "Online" / "Last seen 5 minutes ago" / "Not seen yet" (server view; display only). */
@Composable
fun presenceText(p: Presence?): String = when {
    p == null -> ""
    p.online -> stringResource(R.string.online)
    p.lastSeen != null -> stringResource(
        R.string.last_seen,
        DateUtils.getRelativeTimeSpanString(p.lastSeen!!.toLong(), System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString(),
    )
    else -> stringResource(R.string.never_seen)
}

@Composable
fun DevicesScreen(onBack: () -> Unit, onPairAnother: () -> Unit, onChanged: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var devices by remember { mutableStateOf<List<DeviceEntry>>(emptyList()) }
    var presence by remember { mutableStateOf<Map<String, Presence>>(emptyMap()) }
    var tick by remember { mutableIntStateOf(0) }
    var renaming by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<DeviceEntry?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(tick) {
        val core = withContext(Dispatchers.IO) { Core.get(ctx) } ?: return@LaunchedEffect
        devices = runCatching { core.devices() }.getOrDefault(emptyList())
        presence = runCatching { core.presence() }.getOrNull()?.associateBy { it.id }.orEmpty()
    }
    val me = devices.firstOrNull { it.me }
    val pcs = devices.filter { !it.me }
    val default = Core.target(ctx, pcs)?.id

    SubScreen(stringResource(R.string.menu_devices), onBack, snackbar) {
        if (me != null) {
            item {
                Section {
                    SectionTitle(stringResource(R.string.this_phone))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconTile(R.drawable.ic_phone, size = 44.dp)
                        Spacer(Modifier.width(14.dp))
                        Text(me.name, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
                        TextButton(onClick = { renaming = true }, enabled = !busy) { Text(stringResource(R.string.rename)) }
                    }
                }
            }
        }
        item {
            Section {
                SectionTitle(stringResource(R.string.pcs))
                pcs.forEach { pc ->
                    var menu by remember { mutableStateOf(false) }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconTile(
                            R.drawable.ic_computer,
                            size = 44.dp,
                            container = MaterialTheme.colorScheme.primaryContainer,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.width(14.dp))
                        Column(Modifier.weight(1f)) {
                            Text(pc.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            val status = listOfNotNull(
                                presenceText(presence[pc.id]).ifEmpty { null },
                                if (pcs.size > 1 && pc.id == default) stringResource(R.string.default_target) else null,
                            ).joinToString(" · ")
                            if (status.isNotEmpty()) {
                                Text(
                                    status,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (presence[pc.id]?.online == true) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Box {
                            IconButton(onClick = { menu = true }, enabled = !busy) {
                                Icon(painterResource(R.drawable.ic_more_vert), contentDescription = stringResource(R.string.more))
                            }
                            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                                if (pcs.size > 1 && pc.id != default) {
                                    DropdownMenuItem(text = { Text(stringResource(R.string.make_default)) }, onClick = {
                                        menu = false
                                        Core.setTarget(ctx, pc.id)
                                        tick++
                                        onChanged()
                                    })
                                }
                                DropdownMenuItem(text = { Text(stringResource(R.string.remove)) }, onClick = {
                                    menu = false
                                    removing = pc
                                })
                            }
                        }
                    }
                }
                TextButton(onClick = onPairAnother, enabled = !busy) {
                    Icon(painterResource(R.drawable.ic_add), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.pair_another))
                }
            }
        }
    }

    if (renaming && me != null) {
        var name by remember { mutableStateOf(me.name) }
        AlertDialog(
            onDismissRequest = { renaming = false },
            title = { Text(stringResource(R.string.rename_title)) },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { if (it.length <= 64) name = it },
                    label = { Text(stringResource(R.string.name_label)) },
                    singleLine = true,
                )
            },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    renaming = false
                    busy = true
                    scope.launch {
                        val core = withContext(Dispatchers.IO) { Core.get(ctx) }
                        val err = runCatching { core?.rename(name) }.exceptionOrNull()
                        busy = false
                        tick++
                        if (err != null) snackbar.showSnackbar(errorText(ctx, err))
                    }
                }) { Text(stringResource(R.string.save)) }
            },
            dismissButton = { TextButton(onClick = { renaming = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    removing?.let { pc ->
        var lost by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text(stringResource(R.string.remove_title, pc.name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.remove_body))
                    Spacer(Modifier.size(8.dp))
                    listOf(false to R.string.reason_user, true to R.string.reason_lost).forEach { (value, label) ->
                        Row(
                            Modifier.fillMaxWidth().selectable(selected = lost == value, role = Role.RadioButton) { lost = value },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = lost == value, onClick = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(label))
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    onClick = {
                        removing = null
                        busy = true
                        scope.launch {
                            val core = withContext(Dispatchers.IO) { Core.get(ctx) }
                            val err = runCatching { core?.removeDevice(pc.id, lost) }.exceptionOrNull()
                            busy = false
                            tick++
                            onChanged()
                            snackbar.showSnackbar(if (err == null) ctx.getString(R.string.removed, pc.name) else errorText(ctx, err))
                        }
                    },
                ) { Text(stringResource(R.string.remove_confirm)) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

// ---------------------------------------------------------------- settings

@Composable
private fun SwitchRow(title: String, desc: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun ActionRow(title: String, desc: String, action: String?, onClick: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (action != null) FilledTonalButton(onClick = onClick) { Text(action) }
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var copy by remember { mutableStateOf(Prefs.copyOnReceive(ctx)) }
    var history by remember { mutableStateOf(Prefs.keepHistory(ctx)) }
    var unrestricted by remember { mutableStateOf(true) }
    var confirm by remember { mutableStateOf(false) }
    LifecycleResumeEffect(Unit) {
        unrestricted = ctx.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(ctx.packageName) == true
        onPauseOrDispose {}
    }
    val version = remember { runCatching { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName }.getOrNull().orEmpty() }

    SubScreen(stringResource(R.string.menu_settings), onBack, snackbar) {
        item {
            Section {
                SectionTitle(stringResource(R.string.set_receive))
                SwitchRow(stringResource(R.string.set_copy), stringResource(R.string.set_copy_desc), copy) {
                    copy = it
                    Prefs.setCopyOnReceive(ctx, it)
                }
                SwitchRow(stringResource(R.string.set_history), stringResource(R.string.set_history_desc), history) {
                    history = it
                    Prefs.setKeepHistory(ctx, it)
                }
                TextButton(onClick = { confirm = true }) { Text(stringResource(R.string.history_clear)) }
            }
        }
        item {
            Section {
                SectionTitle(stringResource(R.string.set_system))
                ActionRow(stringResource(R.string.set_notifications), stringResource(R.string.set_notifications_desc), stringResource(R.string.open)) {
                    runCatching {
                        ctx.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName))
                    }
                }
                ActionRow(
                    stringResource(R.string.set_battery),
                    stringResource(if (unrestricted) R.string.set_battery_ok else R.string.set_battery_restricted),
                    if (unrestricted) null else stringResource(R.string.open),
                ) {
                    runCatching { ctx.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ActionRow(stringResource(R.string.set_tile), stringResource(R.string.set_tile_desc), stringResource(R.string.set_tile_add)) {
                        runCatching {
                            ctx.getSystemService(StatusBarManager::class.java)?.requestAddTileService(
                                ComponentName(ctx, SendTileService::class.java),
                                ctx.getString(R.string.share_label),
                                SysIcon.createWithResource(ctx, R.drawable.ic_notify),
                                ctx.mainExecutor,
                            ) {}
                        }
                    }
                } else {
                    ActionRow(stringResource(R.string.set_tile), stringResource(R.string.set_tile_manual), null) {}
                }
            }
        }
        item {
            Section {
                SectionTitle(stringResource(R.string.set_about))
                Muted(stringResource(R.string.about_version, version))
                Muted(stringResource(R.string.about_license))
                TextButton(onClick = {
                    runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/Guidin9/warpshot"))) }
                }) { Text(stringResource(R.string.about_source)) }
            }
        }
    }
    if (confirm) {
        ClearHistoryDialog(onDismiss = { confirm = false }) {
            confirm = false
            scope.launch {
                clearHistory(ctx)
                snackbar.showSnackbar(ctx.getString(R.string.history_cleared))
            }
        }
    }
}
