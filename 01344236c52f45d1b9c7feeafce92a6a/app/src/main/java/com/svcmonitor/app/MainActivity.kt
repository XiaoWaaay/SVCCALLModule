package com.svcmonitor.app

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModelProvider

/**
 * MainActivity v8.0 — SVC Monitor control UI.
 *
 * Flow:
 *   1. User selects target APP (→ get UID)
 *   2. User selects preset or custom NRs
 *   3. User clicks "一键启用监控" → sends uid + preset + enable
 *   4. Events stream in, displayed in real-time
 *   5. User can "停止监控" at any time
 *
 * Tabs:
 *   Tab 0: Dashboard (status + one-click controls)
 *   Tab 1: Filter (NR selection + presets)
 *   Tab 2: Events (live event stream)
 *   Tab 3: Settings (SuperKey, tier2, export)
 *
 * FIX: All tab views are pre-built before observeViewModel() to avoid
 * UninitializedPropertyAccessException on lateinit fields.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var vm: MainViewModel
    private lateinit var logExporter: LogExporter
    private lateinit var tabHost: TabHost

    // ===== State =====
    private var selectedUid: Int = -1
    private var selectedAppName: String = ""
    private var selectedPreset: String = "re_basic"
    private val localSelectedNrs = mutableSetOf<Int>()
    private val filterCheckboxes = mutableMapOf<Int, CheckBox>()

    // ===== Dashboard views =====
    private lateinit var tvVersion: TextView
    private lateinit var tvEnabled: TextView
    private lateinit var tvHooks: TextView
    private lateinit var tvNrsLogging: TextView
    private lateinit var tvTargetUid: TextView
    private lateinit var tvEventsTotal: TextView
    private lateinit var tvTier2: TextView
    private lateinit var tvSelectedApp: TextView
    private lateinit var tvSelectedPreset: TextView
    private lateinit var btnStartStop: Button
    private lateinit var btnSelectApp: Button

    // ===== Events views =====
    private lateinit var eventsListView: ListView
    private lateinit var tvEventCount: TextView
    private var eventsAdapter: EventsAdapter? = null

    // ===== Settings views =====
    private lateinit var etSuperKey: EditText
    private lateinit var switchTier2: Switch

    // ===== Pre-built tab content views =====
    private lateinit var dashboardView: View
    private lateinit var filterView: View
    private lateinit var eventsView: View
    private lateinit var settingsView: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        vm = ViewModelProvider(this)[MainViewModel::class.java]
        logExporter = LogExporter(this)

        // CRITICAL: Pre-build ALL tab views BEFORE setting up observers.
        // This ensures tvEventCount, switchTier2, etc. are initialized
        // before any LiveData callback fires.
        dashboardView = buildDashboard()
        filterView = buildFilter()
        eventsView = buildEvents()
        settingsView = buildSettings()

        buildUI()
        observeViewModel()
        vm.startPolling()
    }

    override fun onDestroy() {
        super.onDestroy()
        vm.stopPolling()
    }

    // ==============================================================
    // Build UI — uses pre-built views
    // ==============================================================
    private fun buildUI() {
        tabHost = TabHost(this, null).apply {
            id = android.R.id.tabhost
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val tabLinear = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val tabWidget = TabWidget(this).apply {
            id = android.R.id.tabs
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val frame = FrameLayout(this).apply {
            id = android.R.id.tabcontent
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }

        tabLinear.addView(tabWidget)
        tabLinear.addView(frame)
        tabHost.addView(tabLinear)
        tabHost.setup()

        // Use pre-built views directly — no lazy init, no lambda factory
        tabHost.addTab(tabHost.newTabSpec("dashboard").setIndicator("监控").setContent { dashboardView })
        tabHost.addTab(tabHost.newTabSpec("filter").setIndicator("过滤").setContent { filterView })
        tabHost.addTab(tabHost.newTabSpec("events").setIndicator("事件").setContent { eventsView })
        tabHost.addTab(tabHost.newTabSpec("settings").setIndicator("设置").setContent { settingsView })

        setContentView(tabHost)
    }

    // ==============================================================
    // Tab 0: Dashboard — one-click monitoring
    // ==============================================================
    private fun buildDashboard(): View {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }

        // Title
        root.addView(makeTitle("SVC Monitor v8.0"))
        root.addView(makeSubtitle("Always-On 内核模块 + APP 过滤控制"))

        // Status section
        root.addView(makeSectionTitle("模块状态"))
        tvVersion = makeStatusRow(root, "版本")
        tvEnabled = makeStatusRow(root, "监控状态")
        tvHooks = makeStatusRow(root, "已安装钩子")
        tvNrsLogging = makeStatusRow(root, "监控系统调用数")
        tvTargetUid = makeStatusRow(root, "目标 UID")
        tvEventsTotal = makeStatusRow(root, "累计事件")
        tvTier2 = makeStatusRow(root, "Tier2 扩展")

        root.addView(makeDivider())

        // One-click monitoring section
        root.addView(makeSectionTitle("一键监控"))

        // Step 1: Select APP
        root.addView(makeHint("第1步: 选择目标 APP"))

        val appRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(8))
        }

        btnSelectApp = Button(this).apply {
            text = "选择 APP"
            textSize = 13f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { showAppSelector() }
        }
        appRow.addView(btnSelectApp)

        tvSelectedApp = TextView(this).apply {
            text = "  未选择 (监控所有 APP)"
            textSize = 13f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        appRow.addView(tvSelectedApp)

        val btnClearApp = Button(this).apply {
            text = "清除"
            textSize = 11f
            setOnClickListener {
                selectedUid = -1
                selectedAppName = ""
                tvSelectedApp.text = "  未选择 (监控所有 APP)"
            }
        }
        appRow.addView(btnClearApp)

        root.addView(appRow)

        // Step 2: Select preset
        root.addView(makeHint("第2步: 选择监控预设"))

        tvSelectedPreset = TextView(this).apply {
            text = "  当前: 逆向基础 (re_basic)"
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
        }
        root.addView(tvSelectedPreset)

        val presetRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val presetRow2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        val presets = StatusParser.presets
        for (i in presets.indices) {
            val p = presets[i]
            val btn = Button(this).apply {
                text = p.label
                textSize = 11f
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .also { it.marginEnd = dp(2); it.marginStart = dp(2) }
                setOnClickListener {
                    selectedPreset = p.name
                    tvSelectedPreset.text = "  当前: ${p.label} (${p.name})"
                }
            }
            if (i < 4) presetRow1.addView(btn) else presetRow2.addView(btn)
        }
        root.addView(presetRow1)
        root.addView(presetRow2)

        root.addView(makeHint("或在\"过滤\"标签页手动选择系统调用"))

        // Step 3: Start/Stop button
        root.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(16))
        })

        btnStartStop = Button(this).apply {
            text = "一键启用监控"
            textSize = 16f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = dp(4) }
            setBackgroundColor(0xFF4CAF50.toInt())
            setTextColor(0xFFFFFFFF.toInt())
            setOnClickListener {
                if (vm.monitoring.value == true) {
                    vm.stopMonitoring()
                } else {
                    // If user has manually selected NRs in filter tab, use those
                    if (localSelectedNrs.isNotEmpty()) {
                        vm.startMonitoringWithNrs(selectedUid, localSelectedNrs.toList())
                    } else {
                        vm.startMonitoring(selectedUid, selectedPreset)
                    }
                }
            }
        }
        root.addView(btnStartStop)

        // Quick actions
        root.addView(makeDivider())
        root.addView(makeSectionTitle("快速操作"))

        val quickRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        quickRow.addView(Button(this).apply {
            text = "清空事件"
            textSize = 12f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .also { it.marginEnd = dp(4) }
            setOnClickListener { vm.clearEvents() }
        })
        quickRow.addView(Button(this).apply {
            text = "立即刷新"
            textSize = 12f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { vm.refreshNow() }
        })
        root.addView(quickRow)

        scroll.addView(root)
        return scroll
    }

    // ==============================================================
    // Tab 1: Filter (NR selection + presets)
    // ==============================================================
    private fun buildFilter(): View {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }

        root.addView(makeSectionTitle("手动选择系统调用"))
        root.addView(makeHint("勾选后需点击\"应用选中\"。手动选择后一键监控将使用自定义列表。"))

        // Action buttons
        val actionRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(4), 0, dp(8))
        }

        actionRow.addView(Button(this).apply {
            text = "应用选中"
            textSize = 11f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .also { it.marginEnd = dp(2) }
            setOnClickListener {
                if (localSelectedNrs.isEmpty()) {
                    Toast.makeText(this@MainActivity, "未选中任何系统调用", Toast.LENGTH_SHORT).show()
                } else {
                    vm.setNrs(localSelectedNrs.toList())
                }
            }
        })
        actionRow.addView(Button(this).apply {
            text = "全选"
            textSize = 11f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .also { it.marginEnd = dp(2) }
            setOnClickListener {
                localSelectedNrs.clear()
                for (cat in StatusParser.categories) {
                    for (sc in cat.syscalls) localSelectedNrs.add(sc.nr)
                }
                syncCheckboxes()
            }
        })
        actionRow.addView(Button(this).apply {
            text = "全不选"
            textSize = 11f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                localSelectedNrs.clear()
                syncCheckboxes()
            }
        })
        root.addView(actionRow)

        root.addView(makeDivider())

        // Quick preset buttons in filter tab too
        root.addView(makeSectionTitle("快速预设 (直接生效)"))
        val pRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val pRow2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        for (i in StatusParser.presets.indices) {
            val p = StatusParser.presets[i]
            val btn = Button(this).apply {
                text = p.label
                textSize = 10f
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .also { it.marginEnd = dp(2); it.marginStart = dp(2) }
                setOnClickListener { vm.applyPreset(p.name) }
            }
            if (i < 4) pRow1.addView(btn) else pRow2.addView(btn)
        }
        root.addView(pRow1)
        root.addView(pRow2)

        root.addView(makeDivider())

        // Category checkboxes
        for (cat in StatusParser.categories) {
            root.addView(TextView(this).apply {
                text = "${cat.icon} ${cat.name}"
                textSize = 15f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setPadding(0, dp(8), 0, dp(4))
            })

            for (sc in cat.syscalls) {
                val cb = CheckBox(this).apply {
                    text = "${sc.nr}: ${sc.name} - ${sc.description}"
                    textSize = 12f
                    isChecked = false
                    setOnCheckedChangeListener { _, isChecked ->
                        if (isChecked) localSelectedNrs.add(sc.nr) else localSelectedNrs.remove(sc.nr)
                    }
                }
                filterCheckboxes[sc.nr] = cb
                root.addView(cb)
            }
        }

        scroll.addView(root)
        return scroll
    }

    // ==============================================================
    // Tab 2: Events
    // ==============================================================
    private fun buildEvents(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(8))
        }

        tvEventCount = TextView(this).apply {
            text = "事件: 0"
            textSize = 14f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        header.addView(tvEventCount)
        header.addView(Button(this).apply {
            text = "清空"
            textSize = 12f
            setOnClickListener { vm.clearEvents() }
        })
        root.addView(header)

        eventsListView = ListView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
            )
            isStackFromBottom = true
            transcriptMode = ListView.TRANSCRIPT_MODE_NORMAL
        }
        eventsAdapter = EventsAdapter()
        eventsListView.adapter = eventsAdapter
        root.addView(eventsListView)

        return root
    }

    // ==============================================================
    // Tab 3: Settings
    // ==============================================================
    private fun buildSettings(): View {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }

        // SuperKey
        root.addView(makeSectionTitle("SuperKey"))
        etSuperKey = EditText(this).apply {
            setText(KpmBridge.getSuperKey())
            textSize = 14f
            isSingleLine = true
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
                override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    KpmBridge.setSuperKey(s.toString().trim())
                }
            })
        }
        root.addView(etSuperKey)

        root.addView(makeDivider())

        // Tier2
        root.addView(makeSectionTitle("Tier2 扩展钩子"))
        root.addView(makeHint("加载额外 20 个系统调用 (ioctl/mount/sendmsg 等)"))
        switchTier2 = Switch(this).apply {
            text = "启用 Tier2"
            isChecked = false
            setOnCheckedChangeListener { _, isChecked -> vm.tier2(isChecked) }
        }
        root.addView(switchTier2)

        root.addView(makeDivider())

        // Export
        root.addView(makeSectionTitle("日志导出"))
        val exportRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, 0)
        }
        exportRow.addView(Button(this).apply {
            text = "导出 CSV"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .also { it.marginEnd = dp(8) }
            setOnClickListener { exportLog("csv") }
        })
        exportRow.addView(Button(this).apply {
            text = "导出 JSON"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { exportLog("json") }
        })
        root.addView(exportRow)

        scroll.addView(root)
        return scroll
    }

    // ==============================================================
    // Observe ViewModel
    // ==============================================================
    private fun observeViewModel() {
        vm.status.observe(this) { s ->
            if (s == null || !s.ok) {
                tvVersion.text = "未连接"
                tvEnabled.text = "---"
                return@observe
            }

            tvVersion.text = s.version
            tvEnabled.text = if (s.enabled) "运行中" else "已暂停"
            tvEnabled.setTextColor(if (s.enabled) 0xFF4CAF50.toInt() else 0xFFFF5722.toInt())
            tvHooks.text = "${s.hooksInstalled}"
            tvNrsLogging.text = "${s.nrsLogging}"
            tvTargetUid.text = if (s.targetUid < 0) "全部" else "${s.targetUid}"
            tvEventsTotal.text = "${s.eventsTotal}"
            tvTier2.text = if (s.tier2) "已加载" else "未加载"

            // Sync filter checkboxes with server state
            // Only auto-sync if user hasn't manually selected anything
            if (localSelectedNrs.isEmpty() || localSelectedNrs == s.loggingNrs.toSet()) {
                localSelectedNrs.clear()
                localSelectedNrs.addAll(s.loggingNrs)
                syncCheckboxes()
            }

            // Sync tier2 switch
            switchTier2.setOnCheckedChangeListener(null)
            switchTier2.isChecked = s.tier2
            switchTier2.setOnCheckedChangeListener { _, isChecked -> vm.tier2(isChecked) }
        }

        vm.monitoring.observe(this) { active ->
            if (active) {
                btnStartStop.text = "停止监控"
                btnStartStop.setBackgroundColor(0xFFFF5722.toInt())
            } else {
                btnStartStop.text = "一键启用监控"
                btnStartStop.setBackgroundColor(0xFF4CAF50.toInt())
            }
        }

        vm.events.observe(this) { events ->
            tvEventCount.text = "事件: ${events.size}"
            eventsAdapter?.updateData(events)
        }

        vm.toast.observe(this) { msg ->
            if (!msg.isNullOrEmpty()) {
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ==============================================================
    // Sync checkboxes
    // ==============================================================
    private fun syncCheckboxes() {
        for ((nr, cb) in filterCheckboxes) {
            cb.setOnCheckedChangeListener(null)
            cb.isChecked = nr in localSelectedNrs
            cb.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) localSelectedNrs.add(nr) else localSelectedNrs.remove(nr)
            }
        }
    }

    // ==============================================================
    // APP selector dialog
    // ==============================================================
    private fun showAppSelector() {
        val apps = AppResolver.getAllApps(this)

        val dialogView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), 0)
        }

        val searchInput = EditText(this).apply {
            hint = "搜索 APP 名称或包名..."
            isSingleLine = true
        }
        dialogView.addView(searchInput)

        val listView = ListView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(400)
            )
        }
        dialogView.addView(listView)

        var filteredApps = apps
        val displayList = mutableListOf<String>()
        displayList.addAll(filteredApps.map { "${it.label} (UID: ${it.uid})" })
        val adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, displayList)
        listView.adapter = adapter

        val dialog = AlertDialog.Builder(this)
            .setTitle("选择目标 APP")
            .setView(dialogView)
            .setNegativeButton("取消", null)
            .create()

        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val q = s.toString()
                filteredApps = if (q.isEmpty()) apps else AppResolver.searchApps(this@MainActivity, q)
                displayList.clear()
                displayList.addAll(filteredApps.map { "${it.label} (UID: ${it.uid})" })
                adapter.notifyDataSetChanged()
            }
        })

        listView.setOnItemClickListener { _, _, pos, _ ->
            if (pos < filteredApps.size) {
                val app = filteredApps[pos]
                selectedUid = app.uid
                selectedAppName = app.label
                tvSelectedApp.text = "  ${app.label} (UID: ${app.uid})"
                dialog.dismiss()
            }
        }

        dialog.show()
    }

    // ==============================================================
    // Export
    // ==============================================================
    private fun exportLog(format: String) {
        val events = vm.events.value ?: emptyList()
        if (events.isEmpty()) {
            Toast.makeText(this, "没有事件可导出", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val file = if (format == "csv") logExporter.exportCsv(events) else logExporter.exportJson(events)
            val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = if (format == "csv") "text/csv" else "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "分享日志"))
        } catch (e: Exception) {
            Toast.makeText(this, "导出失败: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ==============================================================
    // Events adapter
    // ==============================================================
    inner class EventsAdapter : BaseAdapter() {
        private var data: List<StatusParser.SvcEvent> = emptyList()

        fun updateData(newData: List<StatusParser.SvcEvent>) {
            data = newData
            notifyDataSetChanged()
        }

        override fun getCount(): Int = data.size
        override fun getItem(pos: Int): StatusParser.SvcEvent = data[pos]
        override fun getItemId(pos: Int): Long = pos.toLong()

        override fun getView(pos: Int, convertView: View?, parent: ViewGroup?): View {
            val ev = data[pos]
            val layout = (convertView as? LinearLayout) ?: LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(8), dp(6), dp(8), dp(6))
            }
            layout.removeAllViews()

            layout.addView(TextView(this@MainActivity).apply {
                text = "[${ev.nr}] ${ev.name}  pid=${ev.pid} uid=${ev.uid} ${ev.comm}"
                textSize = 12f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(0xFF1565C0.toInt())
            })

            if (ev.desc.isNotEmpty()) {
                layout.addView(TextView(this@MainActivity).apply {
                    text = ev.desc
                    textSize = 11f
                    setTextColor(0xFF333333.toInt())
                    setPadding(dp(8), dp(2), 0, 0)
                })
            }

            layout.addView(View(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 1
                ).also { it.topMargin = dp(4) }
                setBackgroundColor(0xFFEEEEEE.toInt())
            })

            return layout
        }
    }

    // ==============================================================
    // UI helpers
    // ==============================================================
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun makeTitle(text: String) = TextView(this).apply {
        this.text = text
        textSize = 22f
        setTypeface(null, android.graphics.Typeface.BOLD)
        gravity = Gravity.CENTER
        setPadding(0, 0, 0, dp(4))
    }

    private fun makeSubtitle(text: String) = TextView(this).apply {
        this.text = text
        textSize = 12f
        gravity = Gravity.CENTER
        setTextColor(0xFF888888.toInt())
        setPadding(0, 0, 0, dp(16))
    }

    private fun makeSectionTitle(text: String) = TextView(this).apply {
        this.text = text
        textSize = 16f
        setTypeface(null, android.graphics.Typeface.BOLD)
        setPadding(0, dp(8), 0, dp(4))
    }

    private fun makeHint(text: String) = TextView(this).apply {
        this.text = text
        textSize = 12f
        setTextColor(0xFF999999.toInt())
        setPadding(0, 0, 0, dp(4))
    }

    private fun makeStatusRow(parent: LinearLayout, label: String): TextView {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(4), 0, dp(4))
        }
        row.addView(TextView(this).apply {
            text = label
            textSize = 14f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        val tv = TextView(this).apply {
            text = "---"
            textSize = 14f
            setTypeface(null, android.graphics.Typeface.BOLD)
            gravity = Gravity.END
        }
        row.addView(tv)
        parent.addView(row)
        return tv
    }

    private fun makeDivider() = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(1)
        ).also { it.topMargin = dp(12); it.bottomMargin = dp(4) }
        setBackgroundColor(0xFFDDDDDD.toInt())
    }
}
