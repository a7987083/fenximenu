# HFAMap Roadmap

## 当前开发 — v2.3.9-dev IL2CPP Runtime Resolver

基线为 `feature/hfamap-v2-bounded-universal-analyzer@5cb51b1efa15c9303904991fbaa61823a03f9b47`，新分支 `feature/hfamap-v2.3.9-il2cpp-runtime-resolver`。移植 `UnitXP_SP3-Moonstone@a3b8db8651eaea23ec0ae7e5fca497e8f67bcf6c` 的 IL2CPP runtime metadata resolver 思路，并把 Dobby 固定到 `5dfc8546954ce3b3198132ab13fddb89ee92cdd7` 静态链接进 dylib。

本版在已有 resolver/invoke export 观测之外，枚举 Assembly/Class/Method，取得经过 executable Mach-O segment 校验的方法指针，并对最多 96 个与菜单标题及通用动作语义相关的候选入口安装 `DobbyInstrument`。instrument callback 只读取 ARM64 x0-x7/lr/sp，不替换未知签名函数、不主动调用 managed method；停止时逐项 `DobbyDestroy`。

构建状态：实现提交已完成；Actions Run `35722643492` 全步骤成功。产物为 266272-byte arm64 Mach-O，UUID `6AF0A6F6-CD75-3D59-8A42-28DC806996F6`，SHA256 `561e979e0181724dc5f54d43160ae8e698d956ab0016a76839a7c1c9090b3e2d`。CI 验证 Dobby 静态内置，`otool -L` 无外部 Dobby 依赖。

Next Task：

1. XP Hero 分两轮只触发 Currency、Exp，检查 `direct-method-entry` 与最近 UI interaction 的关联；
2. 核对 `backend=embedded-dobby-instrument-reversible`、`resolver.status` 与 direct instrument 安装数；
3. Earn Fuel/Boost 继续保留 static Patch；另做 runtime method 观测，不互相覆盖；
4. 每轮必须 `hooksRestored=true`、`hookRestoreFailureCount=0`；
5. 对 export 被隐藏或枚举 API 不完整的游戏保持 fail-closed，并转 metadata-assisted/internal resolver 后续通道。

## 当前开发 — v2.3.8-dev Dual Runtime Probe

从用户提供并已验证的 v2.3.7 完整源码恢复开发，在既有 `feature/hfamap-v2-bounded-universal-analyzer` 分支追加提交，不改写远端的回退历史。新增 `com.hfa.il2cpp-runtime-probe/v1`：在可逆 Dobby backend 与三个必要 IL2CPP exports 同时存在时，临时观测 `il2cpp_class_from_name -> il2cpp_class_get_method_from_name -> il2cpp_runtime_invoke`，并将 1.5 秒内的 UI 交互与 class/method/instance/argument/result/exception token 关联。

本阶段只做观测，不主动调用解析到的方法，不验证参数签名，不把 runtime method 转成 static patch。XP Hero Currency/Exp 是首个设备验证目标；Enemy Can't Attack 继续走 Legacy/AP。Earn Fuel/Boost 继续走 menu-hook callback field dataflow，不因同为 IL2CPP 游戏而改类。

Next Task：

1. 已完成：Actions Run `35697312404` 编译并交付 v2.3.8 arm64 dylib；
2. XP Hero 连续两轮 Arm，分别只点 Currency、Exp，保存 RuntimeProbe/Diagnostics；
3. 若 exports 或 reversible backend unavailable，保存完整状态，不扩大为不可恢复 inline hook；
4. 对捕获的 assembly/namespace/class/method/parameterCount 与 matching binary+metadata 交叉验证；
5. 只有签名、static/instance、参数编码、异常与返回值门全部闭环后，才开发 direct invocation lane。

## 当前交付 — 成功逻辑完整包

完整包以 `HFAMap_SUCCESS_LOGIC_PACKAGE_README.md` 为入口，包含当前源码、测试、工具、dylib、历史成功链、逐版报告、项目状态和最新六游戏证据。下一开发任务保持不变：property `T/V` backing-state resolver + bounded action sink resolver；XP Hero runtime method call 需先取得 matching artifacts 复核。

## 当前阶段 — v2.3.7-dev `日志2(10)` 多游戏实机验收完成

六款游戏共 12/12 Probe sessions 正常结束，186 raw callbacks、88 logical records，12/12 target list restored、0 restore failure、无第二轮 Arm 闪退。Dragon 第二轮 99 个 slider callbacks 正确合并为 1 条 `1 -> 100` summary。40 条 exact action entry 均成功绑定到 control/target/selector/IMP，但当前全部保持 `unresolved-action-sink`。

自定义控件状态未读出：所有 custom records 均为 `primitiveIvars=[]`、无 `stateChangesAfterEvent`。四份 UUID 匹配菜单二进制已证明共同结构中存在公开 `isOn/currentState` property，其 backing ivar 位于 +56/+80，但 ivar 名被混淆；v2.3.7 的名称过滤在读取前将它们排除。下一版应通用解析 property attributes 的 `T`/`V`，以 property 语义定位 scalar backing ivar，继续保持只读、无 KVC、无未知 selector。

Canonical 未增加也未回退：Earn 20、MeChat 6、XP 1，共 27 static patches；Dragon/Path 9 runtime-only；5 missing-offset。Fuel/Boost 仍由 menu-hook callback field dataflow 自动恢复，不是 Probe 点击生成。

Next Task：

1. 实现 property-backed scalar state provenance，优先验证 Dragon/Earn/Path/Whisper 已静态证明的 `isOn/currentState` 布局；
2. 取得 MeChat/XP matching menu binary，独立验证其 property/backing ivar 布局；
3. action resolver 增加 selector refs 与 bounded internal-call diagnostics，禁止把共享 UI action IMP 当 patch；
4. 重编译下一版并用六款各两轮 OFF→ON/ON→OFF 回归，restore failure 必须保持 0；
5. 只有 handler → target method/field → target UUID/RVA → original/enabled/live bytes 完整闭环后，才新增 Canonical。

实机报告：`HFAMap_v2.3.7-dev_日志2(10)实机验收.md`。

## 上一阶段 — v2.3.7-dev State + Action Sink 已编译

本版补上 `日志2(9)` 暴露的两段通用证据缺口。Runtime Probe 对已选菜单 image 中自定义 `UIControl` 的 class hierarchy 做只读、名称受限的 primitive ivar inventory；记录 Arm 基线、事件回调即时状态、下一主线程周期稳定状态以及逐字段差异。只读取 `B/c/C/s/S/i/I/l/L/q/Q/f/d` 标量，不调用未知 getter、KVC 或 selector，不解引用对象 ivar。

Scan 同时保存精确 `control -> target -> selector/IMP` action seeds，将 menu-local IMP 送入既有 96-byte bounded ARM64 classifier，输出 `actionProvenanceEvidence` 与 `actionSinkClass`。结果仍为 analysis-only，不改变 Canonical 资格门。

验证：62/62 tests；Linux/Theos、iPhoneOS 16.5 SDK、arm64/iOS 12.0 双 clean build 字节一致；211344 bytes；UUID `66BB51DA-E19C-31AD-A170-A1EF955CE9A3`；LC_CODE_SIGNATURE 2048 bytes；SHA256 `06716ac60f7374ad8989928776f8487d8e1132fa992309ecda0a5f4d7c7e115f`。当前目录不是 Git worktree；无 Commit、无 Actions、未实机。

Next Task：

1. Whisper、MeChat、XP 各两轮 Scan + Probe，验证 action entry 与 unresolved identifier 的稳定绑定；
2. Dragon/Path 自定义开关各做 OFF→ON、ON→OFF，要求 `stateChangesAfterEvent` 出现稳定 primitive ivar；
3. Dragon slider 必须继续合并，12/12 类似双轮 restore 仍为 0 failure；
4. 若 action sink 仍 unresolved，扩展 direct-call/indirect-call diagnostics；不得从 action IMP 直接生成 patch；
5. 对 Whisper 匹配 UnityFramework + metadata 开始第二条跨游戏 target method/field dataflow；
6. 回真实 Git worktree提交并运行 Actions。

交付报告：`HFAMap_v2.3.7-dev_StateActionSink交付.md`。

## 文档基线 — Legend 名字解析成功链已纳入

`HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md` 第 8 项已记录 Legend 2.0.3 的外部展示名候选、两轮实机 registry、12 group / 16 descriptor 合并关系和名字 canonical truth gates。下一次拿到 UUID `F4A420C5-E116-3AE9-8943-C2D9E74F4CEC` 的 `LegendofSurvivors.dylib` 后，独立复算 title secret preferred VA，并继续保持网页名称只作候选、同 feature registration 才能绑定的规则。

## 当前阶段 — v2.3.6-dev 多游戏 Interaction Probe 部分实机通过

`日志2(9)` 完成 6 款/12 Probe sessions：180 raw callbacks、96 logical records、12/12 restore checks、0 restore failure、无第二轮 Arm 闪退。Dragon 两轮 39/47 slider samples 分别合并为单一 summary；其余自定义开关稳定分类为 `value-changed`，Path Debug Menu 正确分类为 `touch-up-inside`。

严格未完成项：自定义开关不是 UISwitch，`switchOn` 不存在且 inherited `selected` 始终 false，当前无法证明每次 ON/OFF；Path nested `0x66C4` 仍未自动输出 `0x3DEC9A0`，说明 dlsym pointer-equality fallback 未命中。

Fuel/Boost 本轮继续由通用 `menu-hook-callback-field-dataflow` 自动恢复，7/7 target segments 完整覆盖，结果保持 `0x2D98AC8 / 0x2D9887C` 与正确 original/enabled；不是点击 Probe 直接推导，也不是硬编码地址。

Next Task：

1. 为 custom ValueChanged control 增加只读 class hierarchy 与 state-source evidence，禁止盲目 KVC/未知 selector；
2. Path 输出 dyld stub/GOT/resolved pointer/dladdr/dlsym bounded diagnostics，处理实际设备地址差异；
3. 再做多游戏两轮 Probe，要求 switch state 可验证且 restore failure 保持 0；
4. Fuel/Boost 分别实际启用/关闭，补游戏消耗和 original 恢复证据；
5. 回真实 Git worktree提交并运行 Actions。

实机报告：`HFAMap_v2.3.6-dev_日志2(9)实机验收.md`。

## 已编译阶段 — v2.3.6-dev 多游戏 Interaction Probe

`日志2(8)` 已完成 v2.3.5 多游戏验收：6 款、12/12 Probe sessions、59 次 callback，包含 44 次点击/开关和 15 次真实 slider callback；全部恢复 target list，无重复 Arm 闪退。Heavenfall 是归档中的旧 v2.3.3 文件，不计入 v2.3.5 Probe。

v2.3.6 不按游戏名分支：为 action 输出已注册 `touch-up-inside/value-changed`，将控件分类为 button/switch/slider/ambiguous；同一 slider 的连续 callback 合并为一个逻辑记录并保留首末/极值/sample count，另设 256 callback 上限；停止后反查 sidecar selector，`targetListRestored` 不再写死。Path dyld stub 在 `dladdr` 缺符号名时增加 `dlsym` 地址交叉识别。

验证：60/60 tests；Linux/Theos arm64 双 clean release build逐字节一致；194752 bytes；UUID `CD334EBF-B188-3EBA-84B9-E744F6AE04DB`；SHA256 `60136b22a9d9969d63332ef5a343908a649ee1b097b3ad04bcae1ffc8ec5bda3`。CI 未运行；本段是编译时状态，后续 `日志2(9)` 已完成部分实机验收。

Next Task：

1. Dragon：一轮只拖动 Multiply Attack，要求 v2 summary 为 1 个 slider logical record、sample count > 1、callback count 保留真实采样数；
2. Earn/MeChat/Whisper/XP：各选点击或开关项，核对 `registeredControlEvents` 与 `interactionKind`；
3. Path：点击 Debug Menu，要求 nested `runtime-action-target-resolved` 和 `0x3DEC9A0`；
4. 每款至少两轮，要求 `targetRestoreFailureCount=0`、第二轮无重复 callback、无闪退；
5. 继续保持 runtime action 与 static patch 分层，只有 target bytes 和全部 truth gates 闭环才进入 Canonical。

实机分析：`HFAMap_v2.3.5-dev_日志2(8)实机验收.md`。

## 已完成阶段 — v2.3.5-dev Block Semantic + Runtime Probe

v2.3.4 六游戏/19-session 实机矩阵证明 Block ABI probe 稳定，但 matching binary 同时证明四款公共 `ivar +0x98` Block 都只是 `NSLog(@"iGMM Initialized")`。v2.3.5 新增有界 ARM64 semantic classifier，排除日志 wrapper，并解析 Path 类型的 `dispatch_async -> nested Block -> image slide + preferred RVA` action chain。

新增手动 `Arm Runtime Probe (8s)`：只对策略选中的菜单 image 关联 UIControl 临时添加 sidecar target，记录用户真实触发的 target/action/IMP identity；最多 128 controls / 32 events，超时或手动停止后移除。它不替换 IMP、不调用未知 selector、不全局 Hook、不修改 Canonical。

验证：58/58 tests；Linux/Theos arm64 双 clean build逐字节一致；194704 bytes；UUID `15DB159C-84E3-35E3-81E9-40051A8F1A94`；SHA256 `7712d07d6ada6c1bb87d0f3f5742d96b692ff554198bedbe0e37b91d7c8c2e59`。CI 未运行。后续 `日志2(8)` 已证明 Probe 多游戏稳定，但 Path nested target 解析未通过。

Next Task：

1. Path：Scan 完成后 arm，点击 Debug Menu，要求记录正确 label/target/action，并在 Analysis 中看到 nested action target `0x3DEC9A0`；
2. Whisper/MeChat/XP：分别 arm 后只点击一个 unresolved 功能，确认真实 selector/IMP 是否属于选中菜单；
3. Dragon/Earn/Path/Whisper 的公共初始化 Block 必须分类为 `nonsemantic-logging-block`；
4. 每款执行两次 arm/自动停止，要求 target 全部恢复、无重复回调、无闪退；
5. 只有 runtime target 进一步闭环到静态 target bytes 并通过现有 truth gates，才允许扩展 Canonical。

交付报告：`HFAMap_v2.3.5-dev_RuntimeProbe交付.md`；实机报告：`HFAMap_v2.3.5-dev_日志2(8)实机验收.md`。

## 当前阶段 — v2.3.4-dev Block Provenance Probe 已编译

针对 Whisper/MeChat 的 `missing-offset` 与 Dragon/Path 的 runtime-only 空 Canonical，本版先补齐此前丢失的 handler 入口证据。`日志2(6)` 已证明 Whisper UI target `gIlPAd` 对象图内存在 `__NSGlobalBlock__`，旧扫描器只记录 block 类名，因为系统 Block 类不进入 app-local object traversal，导致其 invoke 函数从未被定位。

v2.3.4 新增通用只读 Block ABI probe：从当前 UI target 对象图中识别 global/malloc/stack block，读取固定 32-byte header，解析 flags、invoke、descriptor；用 dyld identity 将 invoke 映射到镜像、UUID 和 preferred load-base RVA，并读取 32-byte 指令前缀。结果写入 Analysis/FeatureRegistry/Diagnostics 的 `blockProvenanceEvidence`。它不执行、复制、释放或 Hook block，也不把 invoke RVA 当 patch。

验证：53/53 主机测试；Linux/Theos arm64 双 clean build 字节一致；176960 bytes；UUID `00790D66-05CE-363D-91CC-8244A0EC300E`；SHA256 `9938e35952181567d8b4fd3a000c43d8dc5585f4c9993f8043dc573ebc82f6ef`。未运行 Actions，未实机。

Next Task：

1. 用 Whisper 扫描，要求出现 `missing-offset-block/menu-invoke-resolved`，记录 owner ivar offset、invoke RVA 和指令前缀；
2. 同进程连续扫描至少三次，要求 block invoke identity 稳定且不闪退；
3. 对匹配菜单二进制静态分析该 invoke 的 callers/callees、identifier 分支和 APSubpatchManager 交互；
4. 只有能恢复目标 image/RVA/original/enabled 并通过 live-byte gate 后，才扩展 Canonical；
5. 用其他四款回归，确保现有 26 static patches、9 runtime-only 和 unresolved 边界不变。

交付报告：`HFAMap_v2.3.4-dev_BlockProvenanceProbe交付.md`。

## 当前阶段 — v2.3.3-dev 正常覆盖路径实机通过（部分验收）

`日志2(6).zip` 已确认 v2.3.3 在 5 款游戏完成 8/8 sessions，无 error/failed/timeout。Earn 两轮均完整扫描 7/7 executable segments、129974272 bytes，coverage 全部门通过，Fuel/Boost 与 v2.3.2 四轮逐字段一致，稳定输出 14 groups / 20 patches、0 unresolved、0 rejected。

当前严格状态：正常覆盖成功路径已实机验证；计划中的 Earn 五轮只完成 2/5；timeout/read/cap 不完整覆盖拒绝路径尚未做实机故障注入；Fuel/Boost 功能启停仍未验证。

Next Task：

1. Earn 再补至少三轮，达到五轮 coverage/tuple 稳定性门槛；
2. 做 timeout、read failure、segment/global cap、candidate cap 故障注入，要求 0 hook-semantic canonical；
3. Fuel/Boost 分别启用、关闭，验证消耗停止与 original 恢复；
4. 取得第二个具有 callback-field 语义的菜单样本；
5. 回真实 Git worktree提交并运行 Actions。

实机报告：`HFAMap_v2.3.3-dev_日志2(6)实机验收.md`。

## 当前阶段 — v2.3.3-dev Semantic Coverage Gate 已编译

v2.3.3 保留 v2.3.2 已实机成功的菜单 identifier → callback field → target `ldr/fsub/str` 解析链，并补上 canonical 输出前的目标扫描覆盖完整性闸门。只有所有 eligible executable segments 全部读完，且无读失败、deadline、段/全局 byte cap 截断或 candidate cap 命中时，hook-semantic feature 才能进入 Patch v1；否则统一输出 `target-scan-incomplete`，不输出猜测 patch。解析阶段最终跨过 deadline 时，也会撤回本轮已暂存 feature。

当前状态：50/50 主机测试通过；Linux/Theos arm64 两次 clean build 字节一致；176960 bytes；UUID `FF1F1171-6081-3E20-80A8-01C1F74BE1E7`；SHA256 `f63a7474c5c6f51a1d9921048e0db150b70f5e6a961f8503d312f7e6be90e801`。未运行 GitHub Actions，未实机。v2.3.2 仍是最近实机扫描稳定基线。

Next Task：

1. 在 Earn 连续扫描至少五次，要求 `scanCoverage.complete=true`、Fuel/Boost 仍为 14 groups / 20 patches；
2. 做受控 timeout/read-failure/cap 故障注入，要求 `target-scan-incomplete` 且 hook-semantic canonical 数为 0；
3. Fuel/Boost 分别启用、关闭，验证停止消耗和 original 恢复；
4. 取得第二个同类菜单样本验证跨游戏通用性；
5. 回真实 Git worktree 提交并运行 Actions。

交付报告：`HFAMap_v2.3.3-dev_SemanticCoverageGate交付.md`；长期成功过程：`HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md`。

## 当前阶段 — v2.3.2-dev Menu Hook Semantic Resolver 实机扫描通过

`日志2(5).zip` 已证明 Earn 四次连续扫描都能自动恢复 Fuel/Boost 并输出 14 groups / 20 patches；四轮 target UUID、offset、original、enabled 完全一致，0 unresolved、0 rejected。12 款共 23/23 sessions complete，无 timeout/error/failed，扫描耗时均低于 1 秒。

当前严格状态：解析和 JSON 导出已实机验证；Fuel/Boost 真正启用后的停止消耗、关闭后的 original 恢复尚未验证。源码快照仍不是 Git worktree，CI 未运行。

Next Task：

1. Fuel 与 Boost 分别独立启用/关闭，记录游戏数值、HUD 和恢复行为；
2. 做 stale Canonical/sidecar 写入失败故障注入；
3. 取得第二个采用相似 menu-hook 字段语义的游戏样本，验证跨菜单通用性；
4. 回真实 Git worktree，核对 diff、提交并运行 Actions；
5. 通过功能启停和 CI 后再冻结 v2.3.2 stable artifact。

实机报告：`HFAMap_v2.3.2-dev_日志2(5)实机验收.md`。

## 当前阶段 — v2.3.2-dev Menu Hook Semantic Resolver 已编译

已实现通用只读链：当前菜单 registry exact identifier → 菜单 CFString/callback → identifier 对象字段写入 → 当前 App executable field dataflow → live original bytes → canonical Patch v1。解析器不使用 Earn 固定 bundle、UUID 或历史 RVA。

离线全段验证中 Fuel `+0xB8` 原始有两个候选，Boost `+0xBC` 一个；同 callback 多字段共识门把两者收敛到同一目标函数的唯一候选。47/47 主机测试通过；两次 clean arm64 build 一致；dylib SHA256 `5344dde8f5aa39ba822443608bfd3dcde7144dcdfafeb1853fc2c25acaf5048b`。当前状态是“已修改、已编译、离线二进制交叉验证通过、未实机”。

Next Task：

1. Earn matching build 连续扫描五次，要求 Fuel/Boost 每轮唯一解析且 tuple 稳定；
2. 预期 Canonical 为 14 groups / 20 patches，核对 target UUID 和 live original；
3. Fuel/Boost 独立启停，验证停止消耗及 original 恢复；
4. 复测其他菜单，确认新增 executable scan 不超 5 秒且未知家族保持 unresolved；
5. 做 stale-output 故障注入；随后回真实 Git worktree、提交并运行 Actions。

长期成功过程报告：`HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md`。以后每次 offset/patch 成功链变化必须更新该文件。

## 当前阶段 — v2.3.1-dev 共享 offset 已实机通过

输入 `日志2(3).zip` SHA256 `2b31ba45527d117f02aa64ac74cbb94dcc08eeb0efe9ac0fbd84f0e1963ae180`。8 款共 41/41 sessions complete。Rise 五轮稳定得到 3 features / 8 patches，40/40 resolution 唯一命中主程序。总静态证据增至 33 patches；Dragon/Path 的 9 条 runtime-only 语义无回归。

首次归档 `日志2(4).zip` SHA256 `8b3d613ee5529415f038e07f8090b530b1a3b56294c2e429fc51d51efbe13e81`。13 款各完成一次扫描；其中 12 款确认加载 v2.3.1，12/12 complete，共 43 条静态 patch、30 个 feature groups、9 条 runtime-only、12 条 unresolved，sidecar 全部 complete 且 0 rejected/0 deduplicated。当时 Earn 仍加载 v2.3.0 并触发旧 `conflicting-patches-for-target-offset`；该部署问题已由后续五轮复测关闭。

对 Earn 当前 18 条 byte-validated 记录按 v2.3.1 算法离线复核：12 个 feature groups、18 条应输出 patch、0 original overlap 矛盾、0 去重、1 个共享位点；Posters/Prestige 同为 `0x2E25904`，original 重叠 4 bytes 一致。

后续 `新建文件夹.zip` SHA256 `80209a042564ebe31f3b996d14039af784897123ea6aefa2e78ba9e8952b6989` 已确认 Earn 正确加载 v2.3.1。同进程五次扫描全部 complete；每轮 18 validated / 2 unresolved，Patch v1 均为 12 groups、1 target、1 shared site、0 rejected。五轮 18 组 `(identifier,name,target,targetUUID,offset,original,enabled)` 完全一致。最终 Canonical 为 12 groups / 18 patches，sidecar 精确记录 Posters/Prestige 的 `same-offset` 和 4-byte overlap。

本地验证：38/38 主机测试通过；Linux/Theos arm64 两次 clean build 逐字节一致；142288 bytes；SHA256 `5a693b5570e5e3a767e7873579f6f3a3c29b1a4361ff897b472ec8c82cd22d9d`；Mach-O UUID `2273787C-2568-332F-9052-78D3192F6741`。当前源码快照不是 Git worktree，未提交、未运行 GitHub Actions、未实机。

Next Task：

1. 人工放置旧 Canonical/sidecar 后制造 package 构建或文件写入失败，确认陈旧输出被删除；
2. Fuel/Boost 继续保持 unresolved，除非取得当前版本真实 descriptor offset，不复用旧 RVA；
3. 将当前源码放回真实 Git worktree，核对 diff 后提交并运行 Actions；
4. CI 与 stale-output 故障注入通过后冻结 v2.3.1 stable artifact。

### 候选 v2.3.2 — Menu-Anchored Verified Profile Bridge

GitHub 已确认 v1.9.37.10 的 Earn Fuel/Boost 成功链不是菜单自动发现器，而是 exact-build verified profile：菜单负责证明 `Fuel`/`Boost` 按钮当前已加载，离线 IL2CPP/ARM64 分析负责提供 RVA/original/enabled，运行时再以 bundle/version/build、目标 UUID、executable range 和 live original bytes fail closed。

该机制可以通用化为“统一 profile 引擎 + 每构建数据 profile”，但不能把两个 Earn 固定 RVA 当成跨游戏、跨版本通用规则。建议实现：

1. 将 `com.hfa.verified-profile/v1` 从测试 fixture 提升为正式输入 schema，并由构建期生成器编译成只读 profile table；
2. 仅为本轮 registry 中真实存在、当前仍 `missing-offset` 的 identifier 匹配 profile；禁止只按按钮标题全局匹配；
3. 依次要求 bundle ID、short/build version、target image 唯一、target UUID、preferred-VM executable range、live original bytes 全部一致；
4. 通过后追加 `canonicalEligible=true` / `confidence=byte-validated` feature，并记录 `resolutionSource=verified-profile`、profile ID 和证据；
5. Profile 未命中或任一 gate 失败时继续 unresolved，不降低现有菜单 canonical 门槛；
6. IL2CPP 自动语义分析保持离线：binary + matching metadata 验证、method/field/data-flow 恢复、人工确认后生成 profile；禁止在 5 秒实机扫描内进行全镜像启发式推断。

共享 offset 实机报告：`HFAMap_v2.3.1-dev_Earn共享Offset实机验收.md`；12 款矩阵：`HFAMap_v2.3.1-dev_日志2(4)实机分析.md`。

## v2.3.0-dev 开发阶段（历史）

根据 `日志2(2).zip` 的 Rise of Berk 四轮证据，已实现解密 offset 到 canonical gate 的缺失桥梁：解密明文专用的裸十六进制解析，以及按 current executable preferred-VM range 的唯一目标归属。通用 offset 解析未变；零/多命中、patch 跨边界、live original 读取失败或已等于 enabled bytes 均拒绝。

验证状态：35/35 主机测试通过；Linux/Theos arm64 两次 clean build 逐字节一致；141968 bytes；SHA256 `de588af615e7e96058520d0432135992e52b484302d76e3fb4fe52201e41b3cb`。未运行 GitHub Actions，尚未实机。

Next Task：

1. 在 Rise of Berk 连续扫描至少四次，要求 `targetResolution=unique-offset-executable-range`；
2. 验证主程序 UUID、3 canonical features / 8 patches，以及 live original bytes；
3. 比较四轮 `(targetUUID, offset, original, enabled)` 完全一致；
4. 同轮复测 Dragon/Path，确保 runtime-only 输出未被错误提升为静态 patch；
5. 实机通过后再决定是否进入 v2.3.1 的 Backpack/Zombie/Legacy 补全。

阻塞项：Rise original bytes 只能由当前实机目标读取；本地源码不是 Git worktree，无法提交或推送；CI 未运行。

## 上一阶段 — v2.2.9-dev Jailpatch Runtime Evidence（实机验证完成）

输入 `日志2(2).zip` SHA256 `53fbb1382b0a410398722b0b737a7e6398202ac8049a4cfab625c2bd9397096e`。8 款游戏共连续扫描 37 次，37/37 到达 `session/complete`，每款 4–5 次结果稳定；第二次点击闪退未复现。`RuntimeActions.json` 在三款 Jailpatch 共输出 12 条稳定记录，Legacy/AP 继续保持 17 条 canonical patch，且静态包与 v2.2.8 完全一致。

Rise of Berk 已稳定解密 3 个功能的 8 组 offset/enabled bytes，但 descriptor 不含目标镜像字符串，当前 `targetImage=unresolved`。8 个 preferred VM 地址全部且唯一落入主程序 `Dragons-prod-remote-nocheat` 的可执行范围；这已把 v2.3.0 的首要工作收敛为“按解密 offset 唯一映射目标镜像 + live original bytes 真值门”，无需 Hook。

Next Task：

1. 开发 v2.3.0 `unique-offset-range` target resolver；仅在 offset+patch 解密成功且恰好落入一个当前可执行镜像时选择目标；
2. 复用现有 UUID、preferred VM、executable range、live original bytes 校验，预期 Rise 输出 3 features / 8 patches；
3. 添加零命中、多命中、边界、长度、显式目标冲突的 fail-closed 测试；
4. 实机复测 Rise，要求 4 次扫描输出相同 `(targetUUID, offset, original, enabled)`；
5. Dragon/Path 继续保留 RuntimeActions 和 owner metadata，不调用 selector、不 Hook、不写内存。

阻塞项：Rise 的 `original` 只能由下一版在实机当前目标内存读取，现有日志只有 enabled bytes；在 original-byte gate 通过前不得手工制作 Patch v1。源码包仍不是 Git worktree，CI 未运行。

完整分析：`HFAMap_v2.2.9-dev_实机验证与v2.3.0入口.md`。

## 上一阶段 — v2.2.9-dev 开发基线

输入 `日志2(1).zip` SHA256 `f14c31109da24bfb8ba5b71d64af5bd64820fa4e939dc4b6c9e8f7cb38237833`。v2.2.8 在 8 款游戏均完成单次扫描，识别 31 个按钮；Legacy/AP 继续输出 17 条 byte-validated canonical patch，并在所有游戏生成合法 `Canonical.hfapatch.json`。Patch v1 导出因此已实机验证。三款 Jailpatch 共 12 条 UI 配置仍没有静态 patch。

v2.2.9 已完成：

- Jailpatch UI 字典归一化为 `runtimeValue`、`runtimeToggle`、`runtimeAction`，并保留 `staticPatchEligible=false`；
- 新增独立 `com.hfa.igmm.runtime/v1` / `RuntimeActions.json`，不污染 `com.hfa.patch/v1`；
- `C4M0Manager` 从两个固定 selector 检查升级为最多 192 个方法、64 个候选/ivar/property 的有界元数据 inventory；
- 每个方法记录 selector、ABI type encoding、参数数、返回类型、声明类、继承深度、IMP image/path/UUID/RVA 和候选评分；
- 保持 `invoked=false`、`hookInstalled=false`、`written=false`；不恢复 v2.2.1 点击 Hook；
- 31/31 主机测试通过；Linux/Theos arm64 双 clean build 一致，140464 bytes，SHA256 `676f3ae3536637fdb3b215ce434c16f9e00c60891048970294a3b6d03655aa36`。

Next Task：

1. Path of Kings、Dragon Fever TD、Rise of Berk 各扫描一次，收集 `RuntimeActions.json` 与完整 `runtimeEvidence.methodInventory/candidateMethods/ivars/properties`；
2. 同一进程连续扫描三次，验证三个完整 session 和输出稳定性；
3. 先以 Dragon 已知 `loadConfig:`/`loadPolicies` 证据定位真实配置对象边界；取得参数/返回对象结构或精确 iGameGod 二进制之前，不安装 Hook；
4. 根据实机方法表和对象结构开发 v2.3.0 Jailpatch canonical resolver；
5. Posters、Max Level、Backpack、Zombie 的 Legacy 补全作为独立后续版本处理。

当时阻塞项：本地源码包不是 Git worktree，无法记录 branch/HEAD/commit；远程私有仓库需要认证。v2.2.9 当时尚未运行 GitHub Actions 或实机；实机状态已由上方 37-session 验收更新。

## 历史阶段 — v2.2.6-dev Pointer/Decrypt Evidence

已用 v2.2.5 七组实机日志确认：7 款扫描全部完成，27 个按钮被识别，0 canonical patch。GitHub 历史 `feature/hfamap-v1933-original-byte-resolver` 证明 runtime-record 路径曾实机导出 3 功能/8 静态 patch；当前版移植其通用证据链，但拒绝固定 `getter+0xD00` 和历史 RVA。

当前实现仅在 wrapper 所属当前镜像存在唯一 ARM64 指纹时，对有界 secret blob 的 scratch copy 调用解密函数；随后要求目标镜像唯一匹配、UUID、preferred Mach-O VM offset、可执行区间和 live original bytes 全部通过才生成 canonical feature。精确样本静态扫描分别得到唯一候选：Earn `0x9955E4`、Rise `0x2123D4`、Dragon `0x215A74`。

下一任务：先用 Earn to Die Rogue 运行一次干净扫描，验证 `decodeEvidence` 与 canonical 数量；再测 Rise 的擦除类型 `@"?"` 路径；最后用 Dragon 确认 `C4M0Manager/loadConfig:` 实现落在何镜像。v2.2.6 尚未实机验证，不得将静态唯一候选写成实机解析成功。

## 上一阶段 — v2.2.5-dev Evidence Graph（已实机采样）

已完成 v2.2.3 七组日志矩阵：27 个按钮、0 canonical patch、全部 `missing-offset`。三组菜单 UUID 已与二进制精确匹配，并在三份 arm64 菜单中确认 160-byte 描述符的 `offset +0x48`、`signature +0x58` 同构 getter；两者仍是对象 ivar，不是 Patch RVA。

Linux/Theos arm64 交叉编译、链接、strip 与 ldid 签名已通过。下一任务：先在 Earn to Die Rogue 扫描，验证跨镜像 `wrapperClassImage/implementationUUID/rawIvarEvidence`，再在 Dragon Fever/Rise of Berk 验证 Jailpatch 运行时配置对象归属。证据不足时继续 unresolved，禁止恢复点击 hook。

## 历史阶段 — v2.2.3 只读描述符证据

六轮 v2.2.2 扫描已输出 1/1/5/14/1/3 个功能名称，0 个 canonical patch，全部缺少 offset。下一任务：v2.2.3 复测六个菜单注册表中每个功能的描述符字段及菜单 UUID，结合精确版本 Mach-O/UnityFramework 静态分析，不凭 ivar 偏移或旧版本地址生成 patch。完整样本结果及限度见 `HFAMap_v2.2.3_实机日志与开发报告.md`。


## 当前阶段 — v2.2.2 只读注册表（待实机）

目标：以历史已实机验证的 UI target／feature array 关系保留功能名称及关联证据，移除 v2.2.1 点击时 setter hook；本阶段只完成静态真值门。下一任务：六游戏菜单各执行一次 Scan，核对 registry 条数、标签、空 patch 情况和实机稳定性；需要另行提供对应版本二进制与 `.ips` 才能确定新崩溃和原始字节。


## v2.2.0 selected-image descriptor observer

- Implemented locally: image-scoped class enumeration, selector/type filtering, reversible setter observation, bounded capture export.
- arm64 Theos compile/link/sign passed in Actions Run `35431604227` on a temporary build branch; remove the branch after artifact delivery.
- Device gate: confirm correct menu behavior during/after the 20-second window and zero restoration conflicts.
- Evidence gate: correlate captured identifier/offset/signature/range/active fields within the same descriptor instance.
- Canonical gate: map candidate offsets to the exact target image and verify original bytes before exporting patches.

## v2.1.0 first-pass analyzer

Implemented on `feature/hfamap-v2-bounded-universal-analyzer`: short main-thread snapshot, worker-side bounded descriptor analysis, Objective-C family structure evidence, and live detailed diagnostics. Local unit tests and the 11-dylib family regression pass.

Next gates:

1. arm64 Theos CI compile/link/sign;
2. Legacy AP device scan with all diagnostic outputs;
3. Jailpatch device scan and external `loadConfig:` owner evidence;
4. only then add a selected-image-only observer for the verified configuration boundary.

## Current phase — v1.9.37.10 Earn to Die Rogue completion

Branch: `feature/hfamap-v193710-unified-feature-model`

Baseline commit: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`

Verified-profile implementation commit:
`13fff6fd49d84348c618cc7845527e0b5c8413fa`

The `com.notdoppler.earntodierogue` `1.28.251 (1)` scan originally exported
12 canonical features and treated Fuel/Boost as runtime-observed records with
empty patch arrays. Matching IL2CPP metadata and ARM64 data-flow analysis now
prove both are static depletion sites in `Car.FixedUpdate()`.

Current milestone:

- append `Unlimited Fuel` at `UnityFramework + 0x2D98AC8`;
- append `Unlimited Boost` at `UnityFramework + 0x2D9887C`;
- replace only the relevant `fsub` with ARM64 `nop` (`1F2003D5`);
- require exact bundle version, arm64 architecture, UnityFramework UUID and
  original-byte matches before either patch is exported;
- preserve generic resolver behavior for every other title/build.

Next tasks:

1. run a clean device scan and require 14 canonical features / 20 patches;
2. enable Fuel and Boost separately before depletion and verify values/HUD;
3. disable both and verify original-byte restoration;
4. reproduce and resolve the existing Posters/Prestige overlap at
   `UnityFramework + 0x2E25904`.

CI checkpoint:

- run: `35170319783` — success;
- artifact: `10476488771`;
- artifact digest:
  `sha256:3d64e19af748115b1b968ce98a99320948fbeb97d6b28cba4fb364546701b1d4`;
- dylib SHA-256:
  `afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`.

## Current phase

v1.9.36.4 JSONExport — pure parser/exporter, CI passed, **WayOfKings/iGMM device validation passed**, cross-family regression next.

## Product direction

HFAMapUniversal stays focused on:

`original menu -> parser -> evidence -> normalized JSON`

The runtime execution engine is not part of the parser mainline. v1.9.37/v1.9.37.1 merged playback/Dobby into the parser and crashed on device startup, so that direction is retired.

## Stable foundation

- Frozen parser baseline: v1.9.36 ArchitectureTruth, commit `75f94da37221343b6839465ad365ddec2679e63a`.
- Preserve constructor, `run_full_scan()` and resolver/decrypt/original-byte core exactly.
- Canonical static patches remain `com.hfa.patch/v1` with preferred Mach-O VM addresses.
- iGMM runtime behavior remains diagnostic-only under `com.hfa.igmm.runtime/v1`.
- Normalized cross-family analysis uses `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Current milestone: v1.9.36.4

Build checkpoint:

- branch: `feature/hfamap-v19361-json-export`;
- build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`;
- CI run: `34907671999` — success;
- artifact ID: `10372928333`;
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`;
- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`;
- size: `192432` bytes;
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

## WayOfKings/iGMM validation: COMPLETE

Device archive `归档 6(1).zip` confirmed:

- stable injection / no startup crash;
- Full Scan completion;
- 4-feature iGMM diagnostic export;
- normalized analysis export with `status=pass`;
- `Damage Multiplier -> number`, default `1`;
- `Defence Multiplier -> number`, default `1`;
- `God Mode -> toggle`;
- `Debug Menu: kTypeButton -> button`;
- raw Debug Menu primitive/reason preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- target identities for `libpathofkings.dylib` and `UnityFramework` remain correct.

The iGMM path should now be treated as a completed regression checkpoint for this parser line unless new contradictory device evidence appears.

## Next validation: runtime-record/static 5 MB family

Use the same v1.9.36.4 binary. Required evidence:

1. no startup crash;
2. Full Scan completes;
3. canonical `com.hfa.patch/v1` is generated only after the existing truth gates pass;
4. the target image is the intended executable/dylib, not an injected module;
5. target identity UUID/architecture/preferred `__TEXT` values are consistent with the tested binary;
6. every exported `original` byte sequence matches the real target code at the preferred Mach-O VM address;
7. no stale package from a previous run is mistaken for current output;
8. normalized `com.hfa.menu.analysis/v1` reflects the canonical features without changing the static patch contract.

## Following validation: legacy ~15 MB family

After the static 5 MB family passes:

1. run the same v1.9.36.4 parser on the legacy AP/IGSecret-style sample;
2. confirm the historically working static package path still exports correctly;
3. compare control/patch/identity normalization across the 15 MB, static 5 MB and iGMM families;
4. only then promote this parser/exporter line as a cross-family candidate.

## Deferred work

Execution of generated JSON remains a separate project/module. Do not merge it back into HFAMapUniversal without a separately device-validated integration design.
# v2 bounded analyzer roadmap

1. ~~Pass arm64 Theos compile/link/sign CI on the new branch.~~ Completed in run `35186351403`.
2. Validate correct dylib selection and bounded completion on one 14 MiB legacy-ap sample.
3. Validate the same on one 5.75 MiB Jailpatch sample.
4. Use process logs to identify the exact registration/decryption boundary only for families whose descriptors remain runtime-generated.
5. Add a manual candidate picker for legitimate score ties.
6. Promote only after canonical records are independently checked against the target image bytes.

Current next task: add a selected-image-only, read-only observer at the verified `loadConfig:` / runtime-table
boundary. The v2.0.1 five-device matrix completed without hangs or truncation and selected the intended payloads,
but every target still exported zero static descriptors. First fix the pre-policy `selected` event label, then
capture registration arguments and table ownership without invoking unknown getters or scanning process-wide state.

## v2.2.7 rescan checkpoint

- Completed: parsed seven v2.2.6 device sessions; all first scans completed in 208–661 ms.
- Completed: Legacy/AP generic decode path produced 17 byte-validated canonical patches across three apps.
- Completed: fixed MRC lifetime of the `dispatch_once` descriptor signal set and decrypt cache; 21/21 host tests and two identical arm64 clean builds passed.
- Next: on one Legacy/AP target, press `Scan Menu` three times after each completion and confirm three distinct `session/start` + `session/complete` pairs without process restart.
- Then: compare all three runs' canonical `(targetUUID, offset, patch, original)` tuples for exact equality.
- Continue: resolve Backpack/Zombie rejections and Jailpatch runtime-table ownership without weakening fail-closed validation.

## v2.2.8 patch package checkpoint

- Completed: exact `com.hfa.patch/v1` compatibility exporter for byte-validated canonical records.
- Completed: multi-patch feature grouping, runtime package identity/architecture, duplicate suppression and conflicting-slot rejection.
- Completed: 26/26 host tests and two identical Linux/Theos arm64 clean builds.
- Next: device-run Earn to Die Rogue and verify generated `Canonical.hfapatch.json` contains the 15 currently validated patches grouped under 10 feature IDs.
- Next: confirm IDs 5/6 remain absent until Posters/Max Level receive current-build canonical evidence; do not merge historical values automatically.
- Next: repeat the three-scan v2.2.7 stability regression and compare exported v1 packages byte-for-byte after canonical sorting/normalization.

## v2.3.2 Menu Hook Semantic Resolver candidate

- Completed analysis: all three available `EarntoDieRogue.dylib` variants have identical business `__text` and UUID; packaging/signature differences do not provide a second algorithm.
- Completed analysis: Fuel/Boost are implemented by a shared menu-installed hook callback at dylib RVA `0xB88D8C`, not by embedded UnityFramework RVAs.
- Completed analysis: the callback maps `Fuel -> object+0xB8` and `Boost -> object+0xBC`, writes `9999999.0f`, and tail-calls the captured original.
- Completed cross-check: bounded field data flow in the matching Unity function `0x2D9827C–0x2D98FB8` independently reaches `0x2D98AC8` and `0x2D9887C` with the expected original instructions.
- Constraint: historical fixed RVAs remain validation or fallback-profile evidence only; they must not enter the generic discovery resolver.
- Next: implement read-only HookManager/MSHookFunction observation, resolve runtime target VA to image RVA, and add bounded replacement/target ARM64 field-flow analysis.
- Acceptance: Fuel/Boost resolve through `menu-hook-field-dataflow`, with unique-candidate, executable-range and live-original-byte gates; unknown or ambiguous cases remain unresolved.
- Device validation: pending after implementation; current result is static analysis plus binary cross-validation only.

## v2.3.4 `日志2(7)` Block provenance checkpoint

- Completed: 6 games / 19 sessions, all complete; 36 JSON and 12 JSONL / 1222 records parsed without errors.
- Completed: 22/22 Block records remained analysis-only and performed no invoke/copy/release/hook/write operation.
- Completed: Earn 14 groups / 20 patches, MeChat 4 / 6 and XP Hero 1 / 1 remained byte-validated; total 19 groups / 27 patches.
- Falsified: the common owner `ivar +0x98` Block is not a feature handler. Matching Dragon, Earn, Path and Whisper binaries all resolve it to `NSLog(@"iGMM Initialized")`.
- New lead: Path dictionary `kButtonTapHandler -> 0x66B0 -> dispatch_async -> 0x66C4 -> image slide + 0x3DEC9A0` is a real runtime action chain, but currently belongs to Debug Menu and is not a static patch.
- Next Task: add a bounded Block semantic classifier, reject trivial logging wrappers, prefer direct feature-dictionary action fields, and export nested action target provenance without making it canonical.
- Required regression: retain Earn/MeChat/XP tuple outputs exactly; MeChat Points, Whisper Energy/Currency and XP Currency/Exp must remain unresolved unless new target-byte evidence closes the chain.
