# Development Changelog

## v2.3.8-dev — reversible IL2CPP resolver/invoke observation

- 从用户上传的 v2.3.7 完整交付包恢复当前源码，并在既有开发分支追加历史；不覆盖远端故意保留的 v2.1.1 rollback commit。
- 新增 `HFAIL2CPPRuntimeProbe`，动态解析并观测 `il2cpp_class_from_name`、`il2cpp_class_get_method_from_name`、`il2cpp_runtime_invoke`。
- 只在 `DobbyHook` 与 `DobbyDestroy` 同时可用时安装，停止时逐项恢复并记录 restore failure；原函数始终继续执行。
- 记录 assembly/namespace/class/method/parameter count、对象/参数/结果/异常 pointer token，并与最近 1.5 秒 UI 交互相关联；events/mappings 各限 256。
- 本版不主动调用游戏方法、未验证参数签名、`gameStateWritten=false`、`canonicalEligible=false`；临时 Hook 会诚实记录 instrumentation code memory write。
- XP Hero Currency/Exp 作为 runtime-method-call 候选；Enemy Can't Attack 仍为 Legacy/AP。Earn Fuel/Boost 仍为 menu-hook-field-dataflow，不错误改类。
- 新增 6 项源码合同测试并升级 CI；本地 68/68 tests 与 Python compile 已通过。编译、CI 与设备状态将在完成后分别记录。

## v2.3.7-dev — 成功逻辑完整交付包

- 新增 `HFAMap_SUCCESS_LOGIC_PACKAGE_README.md`，汇总菜单识别、feature/container、Legacy/AP、Jailpatch、共享 offset、Fuel/Boost、Patch v1、runtime-only 和 Probe 的完整成功链。
- 交付包包含当前源码、测试、工具、v2.3.7 dylib、全部阶段报告、项目状态文件、`日志2(10)` 原始证据及 XP Hero 专项证据。
- XP Hero 严格分层：当前实机已验证 shared UI action 与 `Enemy Can't Attack` canonical patch；用户提供的 `CheatGetMoney/CheatLevelUp` inner callback 链因缺 matching binary/metadata 暂列待独立复核。
- 本轮不修改运行代码；重新执行主机测试后记录结果。无 Git worktree、Commit 或 CI。

## v2.3.7-dev — `日志2(10)` 六游戏实机验收

- 输入 SHA256 `eef4f73327e517c8f8153bb938f2d1f58fecfff700fc842e9efed73d4dc19ff7`；60 files、42 JSON、12 JSONL、752 JSONL records，0 parse error；全部 entry CRC 通过。
- 12/12 Probe sessions complete；186 raw callbacks、88 logical records；12/12 target list restored，0 restore failure，无第二轮 Arm 闪退。
- Dragon 第二轮真实 slider 99 callbacks 合并为 1 条 summary，值 1→100。
- 六款共取得 40 条 exact action provenance；40/40 `unresolved-action-sink`，没有错误提升为 patch。
- 所有 custom control 均为 `primitiveIvars=[]`、无 `stateChangesAfterEvent`；现有按 ivar 名称过滤未识别混淆 backing ivar。
- 对 UUID 匹配的 Dragon/Earn/Path/Whisper menu binary 静态复核：共同控件均有 `isOn` BOOL property（backing ivar +56）和 `currentState` Q property（backing ivar +80），根因已确认；MeChat/XP 因缺 matching binary 保持推断。
- Canonical 保持 Earn 20、MeChat 6、XP 1，共 27 patches；9 runtime-only、5 missing-offset；Fuel/Boost 结果不变。
- 新增 `HFAMap_v2.3.7-dev_日志2(10)实机验收.md` 并同步长期状态/成功历史。
- 本轮无运行代码修改、无 build、无 Commit、无 CI；v2.3.7 dylib SHA256 仍为 `06716ac60f7374ad8989928776f8487d8e1132fa992309ecda0a5f4d7c7e115f`。

## v2.3.7-dev — custom-control state provenance and action sink entry

- `HFAMapRuntimeProbe.mm` 新增最多 8 层 menu-local class / 32 个 state-like primitive ivar 的只读状态快照；用 `class_getInstanceSize`、ivar offset/width 边界和 `vm_read_overwrite` 防止越界。
- 保存 `stateAtArm`、`stateImmediate`、`stateSettled`、`stateChangesAtCallback`、`stateChangesAfterEvent`；保留 UISwitch/UISlider/UIKit public state，但不把继承的 selected 当成自定义开关真值。
- 禁止 KVC、未知 selector 和对象 ivar 解引用；Probe 仍不替换 IMP、不安装 Hook、不写游戏内存。
- `HFAMapCaptureFeatureSeeds` 新增精确 control/target/selector/event action seeds；Resolver 输出 `actionProvenanceEvidence`，包含 IMP image/UUID/load-base offset、type encoding、bounded semantic evidence 与 fail-closed `actionSinkClass`。
- Analysis 与 FeatureRegistry 均导出 action provenance；所有 action 证据固定 `analysisOnly=true`、`canonicalEligible=false`。
- 新增 2 项源码合同测试；全套 62/62 pass。
- Linux/Theos arm64 双 clean release build 字节一致；211344 bytes；UUID `66BB51DA-E19C-31AD-A170-A1EF955CE9A3`；LC_CODE_SIGNATURE 2048 bytes；SHA256 `06716ac60f7374ad8989928776f8487d8e1132fa992309ecda0a5f4d7c7e115f`。
- 当前目录不是 Git worktree：无 Branch/HEAD/Commit；Actions 未运行；v2.3.7 未实机。v2.3.6 `日志2(9)` 仍是设备基线。

## v2.3.6-dev — `日志2(9)` 多游戏实机验收

- 输入 SHA256 `fa11d09c7a0c8e3fb352a6d1dab2bad73aedcc3cf4141b56f32aa180572a5908`；6 款、60 files、42 JSON、12 JSONL 全部解析成功。
- 12/12 Probe sessions complete；180 raw callbacks、96 logical records；12/12 `targetListRestored=true`、restore failure 总数 0；无 error/failed/timeout 或第二轮 Arm 闪退。
- Dragon 两轮 39/47 slider samples 均各自合并为 1 个 summary，原始 samples 保留在 Diagnostics；slider coalescing 实机通过。
- 事件分类为 86 slider-value-changed、90 value-changed、4 touch-up-inside；Path Debug Menu 与开关准确分离。
- 六款自定义开关均能绑定正确 label/control/action/IMP，但不是 UISwitch，`switchOn` 为空且 `selected` 始终 false；开关 ON/OFF 状态尚未验证。
- Path outer dispatch chain 通过，nested `+0x66C4` 仍为 unresolved；v2.3.6 dlsym fallback 没有恢复 `0x3DEC9A0`。
- Fuel/Boost 继续由通用 `menu-hook-callback-field-dataflow` 自动输出；7/7 segments、129974272 bytes 全覆盖，0 failure/truncation，结果与稳定基线一致。
- Canonical 回归：Earn 14/20、MeChat 4/6、XP 1/1；Dragon/Path runtime-only，Whisper/MeChat/XP missing-offset 边界不变。
- 新增 `HFAMap_v2.3.6-dev_日志2(9)实机验收.md`，同步状态文件和成功历史。
- 本轮无运行代码修改、无新 build、无 Commit、无 CI；v2.3.6 dylib 仍为 SHA256 `60136b22a9d9969d63332ef5a343908a649ee1b097b3ad04bcae1ffc8ec5bda3`。

## v2.3.6-dev — multi-game interaction classification and slider coalescing

- 审计 `日志2(8).zip`：7 款/69 files 全部可解析；其中 6 款为 v2.3.5、12/12 Probe sessions、59 callbacks、12/12 target list restored；Heavenfall 为旧 v2.3.3，无 Probe。
- Dragon 第一轮证明真实 UISlider 连续产生 15 callbacks，并与同名外层功能行使用不同 control/action；Path 的两个 Multiplier 本轮没有 sliderValue，不按名称误判控件类型。
- action evidence 新增 `registeredControlEvents`；新增 `interactionKind`，显式区分 slider、switch、touch、value-change 和 ambiguous custom control。
- slider summary 按 control token 合并，保留 first/last/min/max/sample count；原始 callback 继续写 Diagnostics。32 条改为逻辑 event 上限，新增独立 256 callback 硬上限。
- 停止 Probe 后反查 sidecar selector，输出真实 `targetRestoreFailureCount`；`targetListRestored` 不再写死。
- 修复 Path nested action 的符号解析边界：stub/GOT target 的 `dladdr` 无 `dli_sname` 时，用 `dlsym` 导出地址交叉识别 dyld slide 函数。
- RuntimeProbe schema 升级 `com.hfa.runtime-probe/v2`；版本更新为 `2.3.6-dev-interaction-probe`。
- 新增 2 项测试并扩展 Probe 合同测试；全套 60/60 pass。
- Linux/Theos arm64 两次 clean release build 字节一致；194752 bytes；UUID `CD334EBF-B188-3EBA-84B9-E744F6AE04DB`；LC_CODE_SIGNATURE 1920 bytes；SHA256 `60136b22a9d9969d63332ef5a343908a649ee1b097b3ad04bcae1ffc8ec5bda3`。
- 当前目录不是 Git worktree：无 commit、未运行 Actions；v2.3.6 尚未实机。

## v2.3.5-dev — Block semantic classifier and reversible runtime probe

- 根据 `日志2(7)` 与 matching binaries，确认公共 owner Block 是 `NSLog(@"iGMM Initialized")`，不再作为 feature handler 候选。
- `HFAMapResolver.mm` 新增 bounded ARM64 Block semantic classifier：ADRP/ADD、B/BL、stub/GOT import、CFString、nested global Block、dyld slide + preferred RVA 解析。
- 日志 wrapper 输出 `nonsemantic-logging-block`；Path 类型 action 输出 `runtime-action-dispatch-chain` / `runtime-action-target-resolved`，仍为 analysis-only。
- 新增 `HFAMapRuntimeProbe.mm/.h` 和 `Arm Runtime Probe (8s)` UI。
- Probe 只对已选 menu image 关联 UIControl 添加可逆 sidecar target；记录真实 label、target/action、method type encoding 和 IMP image/load-base RVA。
- Probe 上限为 768 views、128 controls、32 events、2–15 秒；自动或手动停止会移除全部 target，并输出 `RuntimeProbe.json`。
- 未使用 `method_setImplementation`、`objc_msgSend`、`MSHookFunction` 或全局 dispatch hook；不自动调用原菜单功能，不改变 Canonical。
- 新增 5 项源码/生命周期/安全合同测试；全套 58/58 pass。
- Linux/Theos arm64 两次 clean build 字节一致；194704 bytes；UUID `15DB159C-84E3-35E3-81E9-40051A8F1A94`；SHA256 `7712d07d6ada6c1bb87d0f3f5742d96b692ff554198bedbe0e37b91d7c8c2e59`。
- 当前目录不是 Git worktree：无 commit、未运行 Actions、v2.3.5 尚未实机验证。

## v2.3.4-dev — generic read-only Block provenance probe

- 审计并新增 `HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md` 第 8 项“Legend of Survivors 名字解析证据链”；原第 8–14 项顺延为第 9–15 项。
- 用户提供的 iOSGods 原始详情页截图确认 16 个展示项；截图 SHA256 `e6950722637c7cd6413c6db90842236a975696c5bc9cdd1bffca71ed9a954b0b`。
- 两轮实机 registry 均为 12 groups / 16 descriptors，tuple SHA256 均为 `5641a97488f0a4cb0a848b2bf83d33f763a676c785b6c005922670bc54a667c7`；Canonical 均为 12 groups / 16 patches，tuple SHA256 均为 `8843b0fdc148212729a96c260cb472640d12e6fb54cfffc7813de98908072251`。
- 修正原稿的长度候选错误：8-byte plaintext 是 `Skill CD`，35-byte plaintext 是 `⚡ Patrol Reward + Claim Unlimited`；长度不得用于单独定名。
- 静态 title secret preferred VA 表与实机长度/group/descriptor 结构吻合，但当前工作区缺少 UUID `F4A420C5-E116-3AE9-8943-C2D9E74F4CEC` 的菜单 dylib，地址级独立复算仍待补齐。
- 本次仅修改文档和状态文件；无运行代码修改、无新编译、无 Git commit、无 CI、无新增实机运行。
- 根因入口：Whisper 的菜单 UI target 对象图含 `__NSGlobalBlock__`，旧 app-local traversal 不进入系统 Block 类，导致中央 handler invoke 未进入证据链。
- 新增 `HFABlockLiteralHeader` 与 `HFAReadOnlyBlockProvenance`：有界读取 Apple Block ABI 32-byte header，记录 block class、owner class/token、ivar offset、flags、descriptor 和 invoke location。
- invoke 使用 dyld 映射到实现 image/path/UUID/preferred load-base RVA；仅当 invoke 属于当前选中菜单时读取 32-byte 指令前缀。
- 最多保留 32 条去重证据，新增 `missing-offset-block` 诊断、`blockProvenanceRecords` / `menuBlockInvokes` metrics，并输出 `blockProvenanceEvidence` 到 Analysis 与 FeatureRegistry。
- 安全合同：`analysisOnly=true`、`canonicalEligible=false`、invoked/copied/released/hookInstalled/memoryWritten 全为 false；不调用 Block、不解析捕获对象、不生成未验证 patch。
- 新增 3 项 Block ABI、边界、只读和导出合同测试；全套 53/53 pass。
- 版本、标题和 CI 产物升级为 v2.3.4；CI 增加 block provenance 二进制字符串门。
- Linux/Theos arm64 双 clean build 字节一致；176960 bytes；UUID `00790D66-05CE-363D-91CC-8244A0EC300E`；SHA256 `9938e35952181567d8b4fd3a000c43d8dc5585f4c9993f8043dc573ebc82f6ef`。
- 当前目录不是 Git worktree：无 commit、未运行 Actions、未实机。本版尚未取得 Whisper offset/patch。

## v2.3.3-dev — `日志2(6)` partial device validation

- 输入 SHA256 `734e9259b3739853aa344350eecd56d521d4b5c43fc1e3f3d139c888b7a4ccd1`；46 members CRC 通过，30 JSON、10 JSONL / 614 records 全部解析成功。
- 5 款共 8/8 sessions complete；无结构化 error/failed/timeout；第二次 Scan Menu 在 Dragon、Earn、Path 均完成。
- Earn 两轮 `scanCoverage.complete=true`：7/7 segments、129974272/129974272 bytes、0 failed chunks、0 truncated segments、无 deadline、无 candidate cap。
- 两轮均为 14 registry、20 validated、0 unresolved、2 hook-semantic validated、14 groups / 20 patches、0 rejected、1 shared site。
- Fuel/Boost 的 14 项菜单/目标 tuple 两轮一致，并与 v2.3.2 四轮逐字段完全相同。
- 最终 5 款合计 18 groups、26 static patches、9 runtime-only、12 unresolved；5 个 sidecar complete，0 deduplicated、0 rejected。
- 新增 `HFAMap_v2.3.3-dev_日志2(6)实机验收.md`，同步长期成功过程报告和五份状态文件。
- 本轮无运行代码修改、无新 build、无 Commit、无 CI。Earn 仅 2/5 计划轮数，故障注入和功能启停仍待验证。

## v2.3.3-dev — semantic target-scan coverage gate

- 保留 v2.3.2 已实机成功的 Fuel/Boost 菜单语义链，不加入 Earn bundle、UUID 或已知 RVA。
- `HFATargetFieldFlowCandidates` 新增扫描覆盖结果：eligible/complete segments、eligible/attempted/scanned bytes、failed chunks、truncated segments、candidate-cap 和 deadline 状态。
- canonical 真值门要求 eligible segments 全覆盖、读取零失败、零截断、零超时、candidate cap 未命中且 `scannedBytes == eligibleBytes`。
- 覆盖不完整时每个已映射按钮输出 `target-scan-incomplete` 与完整 `scanCoverage`，不生成 canonical feature；最终解析跨过 deadline 时撤回已经暂存的 features/resolved identifiers。
- 新增覆盖模型和源码合同测试，覆盖完整成功、无 eligible segment、读失败、截断、deadline、candidate cap 与 byte mismatch；总测试 50/50 pass。
- 版本更新为 `2.3.3-dev-semantic-coverage-gate`；CI 产物名和字符串断言同步升级，并修正历史上对动态输出名前缀的错误断言，改查真实二进制常量 `Process.jsonl` / `Diagnostics.jsonl`。
- Linux/Theos、iPhoneOS 16.5 SDK、arm64/iOS 12.0 两次 clean build 字节一致；176960 bytes；UUID `FF1F1171-6081-3E20-80A8-01C1F74BE1E7`；SHA256 `f63a7474c5c6f51a1d9921048e0db150b70f5e6a961f8503d312f7e6be90e801`。
- 当前目录不是 Git worktree：无 commit、未运行 Actions、未实机。v2.3.2 设备扫描证据继续作为运行时稳定基线。
- 新增 `HFAMap_v2.3.3-dev_SemanticCoverageGate交付.md`，并同步五份状态文件与长期成功过程报告。

## v2.3.2-dev — `日志2(5)` device validation

- 输入 SHA256 `8ad0e70742992fce5a64a24583f437c7b7c015083d20d59cd9e89ee7afd25c57`；109 ZIP members 内容校验通过，72 JSON + 24 JSONL / 1709 records 全部解析成功。
- 12 款共 23 个 session，23/23 complete；耗时 104.575–970.253 ms；无 timeout/error/failed。
- Earn 四次同进程连续扫描全部得到 14 groups / 20 patches / 0 unresolved / 0 rejected；Fuel/Boost 四轮均由 `menu-hook-callback-field-dataflow` 解析。
- Fuel/Boost 的 identifier、字段、target UUID、offset、original、enabled 四轮一致；tuple-set SHA256 `04fc642c9c2bfd21951b9c8ba0ec36cc5483075afdfd2dd0ecce5fb99e598675`。
- Earn sidecar 20 emitted / 0 deduplicated / 0 rejected / 1 shared site；Posters/Prestige 共享位点无回归。
- 全矩阵 final 输出：43 feature groups、62 static patches、9 runtime-only、12 unresolved；所有 12 个 sidecar complete，0 rejected。
- Dragon/Path 继续保持 runtime-only；MeChat 1、Whisper 2 保持 missing-offset，没有被新路径误升为静态 patch。
- 新增 `HFAMap_v2.3.2-dev_日志2(5)实机验收.md`，并更新长期成功报告和五份状态文件。
- 本轮只分析实机日志并更新文档；没有修改运行代码、没有重新编译、没有 Commit、没有运行 CI。
- 日志未包含实际启停 Fuel/Boost 后的数值与 original-byte 恢复，功能效果仍待单独实机验收。

## v2.3.2-dev — generic menu-hook semantic resolver

- 新增 `HFAMapHookSemantic.mm/.h`：只读解析当前菜单 Mach-O 的 exact identifier、CFString 引用、函数边界、条件分支和常量字段写入，恢复 identifier → object field 语义。
- 一次扫描当前 App executable segments，识别同 base register、同字段的 ARM64 `ldr sN -> fsub sN -> str sN`，从 live 指令生成 original，并以 `nop` 作为 enabled patch。
- 真实 UnityFramework 全段复核发现 Fuel `+0xB8` 原始有两个候选、Boost `+0xBC` 一个候选；新增同菜单 callback 多字段在同镜像/同 base/0x8000 邻域共现门，排除孤立假候选。
- Resolver 不含 Earn bundle、Unity UUID 或 Fuel/Boost 历史 RVA；历史值仅作为测试验收结果。
- 零/多候选保持 unresolved；输出 `hookSemanticEvidence`、raw/filtered candidate count、字段映射和目标数据流。
- 不调用 selector、不安装 Hook、不写内存；5 秒总 deadline、64 MiB 菜单、384 MiB executable、32 mappings/candidates 上限。
- Resolver 内部 feature 判重加入 identifier：同一按钮完全重复仍去重，不同按钮共享相同 offset/patch 仍分别保留。
- 新增 9 项 menu-hook/ARM64/歧义/只读/无硬编码/跨按钮判重回归；全套 47/47 pass。
- Linux/Theos arm64 两次 clean build 逐字节一致；176960 bytes；UUID `FBE89C72-1C29-384A-984A-6E5C8D33A1B7`；SHA256 `5344dde8f5aa39ba822443608bfd3dcde7144dcdfafeb1853fc2c25acaf5048b`。
- 新增长期报告 `HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md`；以后每版涉及 offset/patch 成功链时必须同步维护。
- Git/CI/运行：当前源码快照不是 Git worktree，未提交、未运行 GitHub Actions、尚未实机验证。

## v2.3.1-dev — v1.9.37.10 verified-profile assessment

- 通过 GitHub 插件核对私有仓库分支、Commit、workflow 和 Actions，而非仅依赖旧聊天记录。
- 确认 Fuel/Boost 实现在 Commit `13fff6fd49d84348c618cc7845527e0b5c8413fa`；v1.9.37.10 Actions Run `35170319783` 成功。
- 确认该链为 exact-build hardcoded verified profile，不是菜单自动 offset resolver；v1.9.37.11 主要做发布/CI 加固。
- 对照当前 v2.3.1 registry，Fuel/Boost identifier 均可从已加载菜单稳定取得，适合作为 profile merge 锚点。
- 形成 v2.3.2 候选设计：通用 profile 引擎、构建期 profile table、registry identifier 锚定、exact identity/live-original fail-closed、离线 IL2CPP profile builder。
- 本轮只做 GitHub/源码/日志分析和文档更新；没有修改运行代码、没有新 build、没有 Commit、没有 CI。

## v2.3.1-dev — Earn shared-offset device acceptance

- 输入 `新建文件夹.zip` SHA256 `80209a042564ebe31f3b996d14039af784897123ea6aefa2e78ba9e8952b6989`；9 members CRC 通过，6 JSON + 2 JSONL / 688 records 全部解析成功。
- Earn 五轮均加载 `2.3.1-dev-shared-offset-export`，5/5 sessions complete，耗时 569.56–646.31 ms。
- 每轮 18 validated、2 unresolved；Patch v1 每轮 12 groups、1 target、1 shared site、0 rejected。
- 五轮 18 组完整 tuple 完全一致；tuple-set SHA256 `1e00aefc88c6d2b437efb27743e58e58489692a87315263c2add289cc8eb1f41`。
- 最终 Canonical：12 groups / 18 patches；sidecar：18 emitted、0 deduplicated、0 rejected、1 `same-offset` site、overlapLength 4。
- Posters 与 Prestige 在 `UnityFramework+0x2E25904` 同时保留，证明跨按钮共享 offset 修复实机通过。
- 第二至第五次 Scan Menu 全部完成，v2.3.1 未复现历史二次点击闪退。
- 本轮只分析实机日志并更新文档；没有源码修改、没有新 build、没有 Commit、没有 CI。

## v2.3.1-dev — `日志2(4).zip` device validation addendum

- 输入 SHA256 `8b3d613ee5529415f038e07f8090b530b1a3b56294c2e429fc51d51efbe13e81`；116 ZIP members CRC 通过，76 JSON + 26 JSONL / 858 records 全部可解析。
- 12 款确认加载 v2.3.1，12/12 单次 session complete；30 个 Patch v1 feature groups、43 static patches、9 runtime-only、12 unresolved。
- 12 个 sidecar 均 complete，0 rejected、0 deduplicated、0 shared。
- Rise 8、Backpack 1、Zombie 4 静态 patch 无回归；Dragon 5、Path 4 继续保持 runtime-only。
- Earn 实际加载 v2.3.0，旧全局 slot 规则再次拒绝 Canonical；这不是 v2.3.1 运行结果。
- Earn 18 条记录离线复核 v2.3.1 规则：12 groups、18 emitted、0 original conflicts、1 shared site。
- 本轮只分析日志并更新文档；没有源码修改、没有新 build、没有 Commit、没有 CI。

## v2.3.1-dev — shared offset export

- 修改 `hfamap/src/HFAMapPatchV1.mm/.h`：移除跨 feature 的全局 `target:offset` 冲突规则；新增 range overlap 与 original 逐字节一致性校验。
- 同一 `identifier+title` feature 内按 `target+offset+enabled` 去重；跨 feature 即使 offset/patch 相同也分别保留。
- original overlap 不一致时仅拒绝受影响记录，不再丢弃整个 package。
- 新增 `com.hfa.patch-export-report/v1` sidecar：记录 `sharedPatchSites`、`rejectedRecords`、输入/输出/去重计数。
- 修改 `hfamap/src/HFAMapCore.mm`：Canonical 和 sidecar 使用原子写入；构建或写入失败时删除陈旧输出。
- 版本更新：`hfamap/control`、诊断版本和浮窗标题更新为 v2.3.1-dev。
- 更新 CI：执行完整 `tests/`，产物名和二进制字符串检查升级到 v2.3.1。
- 测试：38/38 pass。
- 构建：Linux/Theos、iPhoneOS 16.5 SDK、arm64/iOS 12.0；两次 clean build 逐字节一致。
- dylib：142288 bytes；UUID `2273787C-2568-332F-9052-78D3192F6741`；SHA256 `5a693b5570e5e3a767e7873579f6f3a3c29b1a4361ff897b472ec8c82cd22d9d`。
- Git/CI/运行：源码快照不是 Git worktree，未提交、未运行 Actions、未实机验证。

## v2.3.0-dev — device validation addendum

- 输入 `日志2(3).zip` SHA256 `2b31ba45527d117f02aa64ac74cbb94dcc08eeb0efe9ac0fbd84f0e1963ae180`。
- 8 款游戏 41/41 sessions complete；每款 5 次，Dragon 6 次；耗时 152.89–622.21 ms。
- Rise 五轮均输出 3 features / 8 patches；40/40 `targetResolution` 为 unique、matchCount 1、目标 UUID 一致；8 组 original/enabled tuple 五轮完全相同。
- Backpack 从 0 恢复 1 patch，Zombie 从 0 恢复 4 patches，Earn 从 15 增至 18 patches；证明裸十六进制修复覆盖纯数字和含 A–F 两类明文。
- 静态总证据为 33 patches；runtime-only 为 Dragon 5 + Path 4；unresolved 为 11。
- Earn 的 Posters/Prestige 共同使用 `UnityFramework+0x2E25904`；两条 original 前缀一致，属于用户确认允许的跨按钮共享补丁位点，不应导致整包拒绝。v2.3.0 的全局 `target+offset` 判重过严，五次 Patch v1 因而均 fail closed；v2 Patches/Analysis 仍保留 18 条证据。
- v2.3.1 设计修正为：跨 feature 保留共享 offset 的每条语义记录；只在同 feature 内做完全相同 patch 去重；重叠 original 证据不一致才拒绝相关记录，并在 sidecar 输出 `sharedPatchSite` 关系及交互风险。
- 发现拒绝路径不会清除旧 Canonical 文件的 stale-output 风险；列为 v2.3.1 首要修复。
- 本轮只分析日志并更新文档，没有修改源代码、没有新 build、没有 CI。
- 新增 `HFAMap_v2.3.0-dev_实机验证与冲突分析.md`。

## v2.3.0-dev — Jailpatch decoded target resolution

### 根因修复

- 新增 `HFADecodedOffsetValue`。解密 descriptor offset 无论是否带 `0x` 均按十六进制完整解析；修复裸值含 `A–F` 时失败、纯数字裸值被误当十进制的问题。
- 通用 `HFAOffsetValue` 保持 base-0，不改变旧家族普通字段语义。
- 新增 `HFAExecutableImageResolutionForDecoded`。当 descriptor 没有 target 字符串时，仅在 offset+patch 完整且唯一落入一个 current executable preferred-VM range 时归属目标。
- 输出 `targetResolution` 证据，包括 status/source/matchCount、target image/UUID/path/vmaddr/vmsize。
- 零命中、多命中、patch 跨边界、无效 offset/patch 全部 fail closed；显式 target 不被推断覆盖，仍由 canonical range gate 校验。
- `HFACanonicalPatchFromDecoded` 继续要求 live original bytes，且拒绝当前字节已等于 enabled patch。

### 修改文件

- `hfamap/src/HFAMapResolver.mm`
- `hfamap/src/HFAMapDiagnostics.mm`
- `hfamap/src/HFAMapEntry.mm`
- `hfamap/control`
- `tests/test_decoded_offset_target_resolution_source.py`
- `tests/test_jailpatch_runtime_evidence_source.py`
- `README.md`、`ROADMAP.md`、`HANDOFF.md`、`PROJECT_STATE.json`、`KNOWN_ISSUES.md`
- `HFAMap_v2.3.0-dev_目标镜像归属与交付.md`

### 验证

- 主机测试：35/35 pass。
- Rise 8 个日志地址的静态模型全部唯一映射主程序；零/多命中和跨边界用例通过。
- Linux/Theos iPhoneOS 16.5 SDK，arm64 iOS 12.0：compile/link/strip/ldid pass。
- 两次 clean build byte-identical。
- dylib：141968 bytes；SHA256 `de588af615e7e96058520d0432135992e52b484302d76e3fb4fe52201e41b3cb`；Mach-O UUID `438D21D8-266A-3AEE-AD80-A0CA1A07479F`。
- Git：当前源码包不是 worktree，未提交、未推送。
- CI：未运行。
- 实机：v2.3.0 未验证；不得提前声明 Rise 已导出 original 或 canonical patch。

## v2.2.9-dev — device validation addendum

- 输入 `日志2(2).zip` SHA256 `53fbb1382b0a410398722b0b737a7e6398202ac8049a4cfab625c2bd9397096e`。
- 8 款游戏 37/37 个 session 完成，每款连续 4–5 次；耗时 137.38–620.73 ms，计数与语义逐次稳定。
- 第二次点击 `Scan Menu` 必闪退未复现；v2.2.7 的 MRC process-lifetime 静态对象修复现有实机回归证据。
- `RuntimeActions.json` 实机生成：Dragon 5、Path 4、Rise 3，共 12 条；Path 的 number/toggle/button 归一化与历史 v1.9.36.4 一致。
- Dragon `C4M0Manager` inventory 为 23 methods / 18 candidates，精确定位 `loadConfig:` 与 `loadPolicies`；全程未调用、未 Hook、未写内存。
- 8 个 Patch v1 包与 v2.2.8 完全一致：12 feature groups / 17 patches，证明新增 runtime bridge 未污染静态导出。
- Rise 四轮均稳定解出 3 功能 / 8 组 offset+enabled bytes；0 canonical 的直接原因是 descriptor 无目标镜像字符串，当前 resolver 缺少按 offset executable range 唯一归属的回退。
- 本次只分析日志并更新文档，没有修改运行时代码或重新编译；CI 仍未运行。
- 新增 `HFAMap_v2.2.9-dev_实机验证与v2.3.0入口.md`，并更新长期状态文件。

## v2.2.9-dev — Jailpatch/iGMM runtime evidence bridge

### Runtime evidence and normalization

- 根据八游戏 v2.2.8 实机日志，将 Jailpatch 无静态字节的 UI 配置从笼统 `missing-offset` 分为 `runtime-value-not-static-bytes`、`runtime-toggle-not-static-bytes`、`runtime-action-not-static-bytes`。
- 新增 `normalizedControl`、`normalizedExecutionPrimitive`、`normalizedCanonicalReason`、`analysisOnly`、`staticPatchEligible`；保留安全的 default scalar 和 `handlerPresent`，不导出 block 地址。
- 新增 `<App>_HFAMap_RuntimeActions.json`，schema 为 `com.hfa.igmm.runtime/v1`。运行时语义与静态 `com.hfa.patch/v1` 分离，存在 offset/patch 字段的静态候选不会被误分类为 runtime record。
- `Analysis.json` 新增 `runtimeRecords`；metrics 新增 `runtimeRecords`；Diagnostics 新增 `runtime-feature/classified` 与 `runtime-export/complete`。

### Jailpatch owner inventory

- 将 `C4M0Manager` 的两个固定 selector 探测扩展为有界 method/property/ivar metadata inventory。
- 最大记录 192 个方法、64 个候选方法、64 个 ivar、64 个 property；同时枚举实例类与元类以及有限继承链。
- 每条方法记录 selector、method kind、declaring class、inheritance depth、type encoding、argument count、return type、IMP image/path/UUID/RVA、system/menu-image 归属和候选评分。
- `loadConfig:`/`loadPolicies` 仍作为已知高置信入口，但不再是识别其他变体的必要条件。
- 安全合同固定为 `metadata-only-no-selector-invocation-no-hook-no-memory-write`；未加入 `objc_msgSend`、`method_invoke`、`method_setImplementation` 或 `vm_write`。

### Files changed

- `hfamap/src/HFAMapResolver.mm`
- `hfamap/src/HFAMapCore.mm`
- `hfamap/src/HFAMapDiagnostics.mm`
- `hfamap/src/HFAMapEntry.mm`
- `tests/test_read_only_registry_source.py`
- `tests/test_jailpatch_runtime_evidence_source.py`
- `README.md`、`ROADMAP.md`、`HANDOFF.md`、`PROJECT_STATE.json`、`KNOWN_ISSUES.md`
- `HFAMap_v2.2.9-dev_成功逻辑与运行时证据.md`

### Verification

- 主机测试：31/31 通过。
- Linux/Theos：arm64 compile/link/strip/ldid 通过。
- 两次 clean build：逐字节一致。
- dylib：140464 bytes，SHA256 `676f3ae3536637fdb3b215ce434c16f9e00c60891048970294a3b6d03655aa36`。
- Mach-O：64-bit arm64 dylib，`NOUNDEFS|DYLDLINK|TWOLEVEL|NO_REEXPORTED_DYLIBS`。
- 二进制字符串验收：v2.2.9 版本、`com.hfa.igmm.runtime/v1`、`RuntimeActions.json` 和只读安全策略均存在。
- Git：当前源码包不是 worktree，未提交、未推送。
- CI：未运行。
- 实机：v2.2.9 未验证；v2.2.8 单次扫描和 Patch v1 输出已由八游戏日志验证。

## v2.2.8-dev runtime validation addendum

- 输入 `日志2(1).zip` SHA256 `f14c31109da24bfb8ba5b71d64af5bd64820fa4e939dc4b6c9e8f7cb38237833`。
- 8/8 个 v2.2.8 session 到达 `session/complete`；31 个按钮被识别；旧七款菜单 UUID、家族、registry/validated/unresolved 数量均无回归。
- 八款均生成合法 `Canonical.hfapatch.json`；Archery 1、Earn 15、Heavenfall 1，共 17 条 canonical patch。
- Earn 导出 10 个 feature group / 15 patches；IDs 5/6 继续因本轮无 canonical 证据而缺席。
- 这证明 Patch v1 导出已实机生成；不证明同一进程连续第二次扫描已修复。

## v2.2.8-dev — canonical `com.hfa.patch/v1` export

- 新增 `HFAMapPatchV1.mm/.h`，将已通过 canonical truth gates 的记录导出为 `package/targets/features/schema/name` 格式。
- 同一 `identifier + title` 的多条 patch 聚合在同一 `patches` 数组；字段映射为 `original`、`enabled`、preferred Mach-O VM `offset` 和 `target`。
- 只接收 `canonicalEligible=true` 且 `confidence=byte-validated` 的记录；校验 offset、hex 字节和 original/enabled 等长。
- 同一 target+offset 出现不同 original/enabled 时整包 fail closed，诊断写入 `patch-v1-export/rejected`。
- `bundleIdentifier`、短版本、build 版本从当前 `NSBundle` 读取；运行切片通过主 Mach-O `cputype/cpusubtype` 区分 arm64/arm64e，不复用样本常量。
- 保留 `Patches.json` v2 证据文件，另写 `<App>_HFAMap_Canonical.hfapatch.json`；选择失败时覆盖为空包，避免旧产物污染。
- 新增 5 项导出器回归测试；全套 26/26 通过。
- Linux/Theos arm64 compile/link/strip/ldid 两次 clean build 逐字节一致；108576 bytes，SHA256 `e5ab1eaf03bc91bdaa709f080cd1730f07549f97475d54b3730bd2f8a98020cb`。
- CI 未运行；发布时尚未实机，后续八游戏 `日志2(1).zip` 已确认兼容包生成，详见上方 runtime validation addendum。

## v2.2.7-dev — second-scan lifetime fix

- 解析输入归档 `日志2.zip`（SHA256 `7c8e1cd0129c98e55cdd890435c283b2ed36b1020abc4469f1dbb6d3da196280`）：7/7 个 v2.2.6 首轮 session 均到达 `session/complete`，耗时 208–661 ms。
- Legacy/AP 解密和 canonical gate 首次获得实机正结果：Earn to Die Rogue 15 条、Archery Clash 1 条、Heavenfall Arena 1 条，共 17 条 byte-validated patch；其余 4 款保持 15 条 unresolved。
- 定位重复扫描崩溃的高置信根因：Theos 编译命令没有 `-fobjc-arc`，而 descriptor signal set 与 decrypt-candidate cache 使用 autorelease convenience constructor 存入 `dispatch_once` 静态指针；首轮 worker autorelease pool 排空后，第二轮访问悬空对象。
- 将两处 process-lifetime static 改为 `alloc/init`，兼容 MRC 与 ARC；未改变 offset、patch、UUID、可执行区间或 live-original 校验。
- 新增 3 项 rescan lifetime 源码回归测试；全套主机测试 21/21 通过。
- Linux/Theos arm64 compile/link/strip/ldid 两次 clean build 逐字节一致；108432 bytes，SHA256 `0862dcaa83de639ac9afd4fe88318925e928914315b1af7aaccc226f9f8972de`。
- CI 未运行；归档无 `.ips`，根因尚无崩溃指令级证明；v2.2.7 尚未实机连续扫描验证。

## v2.2.0-dev — selected-image descriptor observer

- Added a 20-second, manually armed observer for descriptor setters in the selected menu image.
- Class enumeration uses `objc_copyClassNamesForImage`; process-wide `objc_getClassList` is not used.
- Hook eligibility requires structural selector evidence, a directly owned method, supported Objective-C type encoding, and an IMP owned by the selected image.
- Supported argument ABIs: object, BOOL, signed/unsigned 32-bit, signed/unsigned 64-bit, and `NSRange`.
- Every hook preserves and forwards the original IMP. Manual stop and timeout restore the original implementation and report restoration conflicts.
- Added bounded object snapshots and `HFAMap_DescriptorCapture.json`; live events also go to the existing diagnostic JSONL/log.
- Existing preferred-Mach-O-VM-address and live-byte truth gates remain unchanged.
- Host source/triage tests: 10/10 passed in Actions Run `35431604227`.
- iOS arm64 compile/link/strip/sign: passed in Actions Run `35431604227`, commit `ec0621c4566774d2bf0346e59e6c48a2f23a9c26` (temporary build branch).
- Binary SHA-256: `f64244d826c7862814e53b4f783d376c889bba65fdf0daa1a8bd56122cb731e1`.
- Device injection and functionality remain unverified.

## v2.1.1-dev — restore full loaded-image coverage

- Restored the bounded image ceiling from 512 to 2048 after the v2.1.0 eight-run archive showed 947–987 loaded images and five false `no-loaded-menu-image` results.
- Added `appOwnedImages`, `fingerprintedImages`, and `hitImageLimit` discovery metrics.
- Added bounded per-container diagnostics with class, instance size, descriptor signal, field names and child value classes.
- Runtime archive SHA-256: `7747010a7d432ad0706673f3b6a83c2aa8ffee0ad26252b2275c16e193296595`.

## v2.1.0-dev — first-pass family analyzer and live diagnostics

- Split UI capture from descriptor analysis: main-thread work is capped at 350 ms; object graph analysis runs on the serial worker queue.
- Added Objective-C structural evidence: image class count and the stable 160-byte descriptor selector signature.
- Added live `HFAMap_Diagnostics.jsonl` and `HFAMap_Diagnostics.log` with session ID, elapsed time, thread, stage, candidate scores, accepted features and rejection reasons.
- Added descriptor class/size/family/field evidence to canonical and unresolved records.
- Added explicit `preferred-mach-o-vmaddr` semantics and optional declared target-image filtering.
- Renamed the pre-policy discovery field from `selected` to `topCandidate`.
- Added the 11-dylib archive manifest; local family regression passed 11/11.
- Host unit tests passed 4/4. GitHub Actions run `35403381939` passed compile/link/sign at commit `3ad558978f8bd648fefa737bd80f6c5596507426`.
- Artifact `10570699914`; arm64 dylib size `91456`; SHA-256 `5903e172814bf9950ceceb55440adeff1747deffb2cbecec8755017517db6246`.
- Device verification remains pending.

## v1.9.37.10 — verified Earn to Die Rogue Fuel/Boost profile

Branch: `feature/hfamap-v193710-unified-feature-model`

Baseline: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`

Implementation commit: `13fff6fd49d84348c618cc7845527e0b5c8413fa`

Build commit: `5db1f384c49a4a4cd243b722881083f0893692e5`

GitHub Actions run: `35170319783` — success

Artifact ID: `10476488771`

Artifact digest:
`sha256:3d64e19af748115b1b968ce98a99320948fbeb97d6b28cba4fb364546701b1d4`

Binary SHA-256:
`afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`

### Changed

- Added a post-v1.9.37.10 generation step that appends two exact-build static
  features only after bundle/version/architecture/UUID/original-byte checks.
- Added `Fuel`: RVA `0x2D98AC8`, original `0038211E`, enabled `1F2003D5`.
- Added `Boost`: RVA `0x2D9887C`, original `0038281E`, enabled `1F2003D5`.
- Added the binary/metadata evidence report and a machine-readable profile
  fixture.
- Added GitHub Actions assertions for the profile, UUID, RVAs, byte sequences
  and final binary markers.

### Verification

- GitHub remote branch/base commit check: passed;
- matching metadata pair: byte-identical, version 31;
- IL2CPP `Car.FixedUpdate()` mapping: passed;
- ARM64 disassembly/data-flow review: passed;
- existing canonical original bytes: `18/18` matched;
- new Fuel/Boost original bytes: `2/2` matched;
- full local generation chain: passed;
- generated-source fixture assertions: passed;
- Python syntax / JSON syntax / workflow YAML parse: passed;
- `git diff --check`: passed;
- iOS compile/link/sign: passed;
- downloaded artifact ZIP integrity/re-hash: passed;
- built arm64 Mach-O and profile marker inspection: passed;
- device runtime/regression: pending.

## v1.9.36.4 JSONExport — CI passed / WayOfKings device passed

Branch: `feature/hfamap-v19361-json-export`
Parser baseline: `v1.9.36 ArchitectureTruth @ 75f94da37221343b6839465ad365ddec2679e63a`
Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`
Successful CI run: `34907671999`
Artifact ID: `10372928333`
Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
Binary size: `192432` bytes
Binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`

### v1.9.36.4 device result

WayOfKings device archive `归档 6(1).zip` confirmed:

- injection did not crash;
- Full Scan completed;
- `com.hfa.igmm.runtime/v1` regenerated with 4 features;
- `com.hfa.menu.analysis/v1` regenerated;
- `JSON-EXPORT` reported `status=pass features=4 sources=1 targetIdentities=2`.

Normalized controls and evidence:

- Damage Multiplier: `modtext -> number`, default `1`;
- Defence Multiplier: `modtext -> number`, default `1`;
- God Mode: `customSwitch -> toggle`;
- Debug Menu: `kTypeButton -> button`;
- Debug Menu raw `executionPrimitive = nativeHook` preserved;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction`;
- Debug Menu raw `canonicalReason = runtime-hook-requires-portable-equivalent` preserved;
- Debug Menu `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- Damage/Defence normalized reason = `dynamic-numeric-state-not-static-bytes`;
- God Mode normalized reason = `runtime-hook-requires-portable-equivalent`.

Target identities remained stable:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype 6, text VM `0x0`, cryptid 0;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype 6, text VM `0x0`, cryptid 0.

Conclusion: the v1.9.36.4 WayOfKings/iGMM path is device-confirmed. No further WayOfKings normalizer changes are required without new contradictory evidence.

### Verification

- baseline constructor preserved: PASS;
- baseline `run_full_scan()` preserved: PASS;
- baseline trace/resolver core preserved: PASS;
- WayOfKings normalization fixture: PASS;
- analysis-only invariants: PASS;
- arm64 compile/link/strip/sign: PASS;
- no Dobby symbols in final binary: PASS;
- artifact upload/re-hash: PASS;
- v1.9.36.4 WayOfKings device validation: PASS;
- runtime-record/static 5 MB current-line regression: PENDING;
- legacy ~15 MB current-line regression: PENDING.

## v1.9.36.3 JSONExport — device passed on WayOfKings

- Added evidence-preserving `normalizedExecutionPrimitive`.
- Added read-only `targetIdentities`.
- Device archive confirmed stable startup, scan, button normalization and target identity output.

## v1.9.36.2 JSONExport — CI passed

- Added exact `kTypeButton -> button` normalization.

## v1.9.36.1 JSONExport — device tested on WayOfKings

- Rebased onto the stable v1.9.36 parser.
- Added analysis-only serializer after Full Scan.
- Device archive proved stable injection and JSON export, and exposed the `kTypeButton` gap.

## Retired experiment: v1.9.37 / v1.9.37.1

- Combined parser, dynamic JSON UI, playback consumer, Dobby and runtime takeover into one dylib.
- CI/build succeeded, but both device injections crashed at startup.
- Combined architecture abandoned for the HFAMapUniversal parser mainline.

## Earlier parser checkpoints

- v1.9.36: ArchitectureTruth frozen parser baseline.
- v1.9.35: MainImageTruth.
- v1.9.34: CanonicalTruthGate.
- v1.9.33: multi-source original-byte resolver.
- v1.9.32: crash-safe Full Scan.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
# v2.0.0-dev — bounded universal analyzer

- Replaced the compiled legacy/generator chain with four explicit v2 modules.
- Removed recursive app-directory scanning, whole-file mapping, process-wide class scans, unknown getter invocation and broad runtime hooks from the active path.
- Added loaded-image, named-section menu discovery with hard image/byte/time limits.
- Added multi-evidence family classification and ambiguity rejection.
- Added same-descriptor name/offset/patch extraction plus unique executable-range and live-byte validation.
- Split canonical, analysis and process-log outputs.
- Added a read-only host triage tool, synthetic parser tests and a 10-sample SHA/family regression manifest.
- Fixed four Objective-C++ pointer conversions reported by the first macOS build.
- GitHub Actions run `35186351403`: host tests, invariants, arm64 compile/link and artifact upload passed.
- Built binary SHA-256: `d6605ec4b3c36bd3daa7d944d9cd24f230dc4905d33ac67ab5659557b6d57413`.
- Device runtime validation remains pending.
# v2.0.1-dev — first device-log corrections

- Parsed five nested device archives from input SHA-256 `2f92bfc64b37c47a57cfcf42b9e5b84594f401d5cb10877d23f1c67a74f65855`.
- Confirmed bounded scans completed quickly and did not hang.
- Raised the dyld image cap from 512 to 2048 after three runs exhausted the old cap before reaching late-loaded menu images.
- Added descriptor-strength tie-breaking for a generic legacy shell (`97`) versus a full Jailpatch payload (`89`, Jailpatch evidence `116`).
- Stopped recursively turning UIKit/Foundation implementation objects into duplicate `missing-offset` features.
- Confirmed the 5 MB Jailpatch family still needs an evidenced `loadConfig:`/runtime-table observer; no static patch was claimed.

### v2.0.1 five-device result

- Parsed the v2.0.1 re-test archive with SHA-256 `91fbbfa901d3a75cb35d97dcde58d745a1a75e627532ff4242537f024a661b74`.
- All five bounded scans completed in 86.8–137.0 ms while inspecting every loaded image (948–985 images); no hang or image-cap truncation occurred.
- Correctly resolved `MarmotDefenseRogueSurvival.dylib`, `ArcheryClash.dylib`, `libdragonfevertd.dylib`, `libRiseofBerk.dylib`, and `heavenfallarena.dylib`.
- Descriptor-only traversal reduced the previous UIKit/Foundation noise to one or two relevant unresolved records per run.
- All five runs still produced zero byte-validated canonical features. The runtime-generated descriptor boundary is now the confirmed blocker.
- Found a process-log presentation defect: image discovery reports the sorted first candidate as `selected` before the selection policy runs. The resolver and final analysis used the correct `libRiseofBerk.dylib`; only the discovery event label was stale.
# v2.2.2 read-only registry

独立源码版本；GitHub 主开发分支保留 `85a9b9b`。删除 v2.2.1 的点击 setter hook／捕获按钮，加入菜单 target 可达功能字典注册表、逐功能名称传播、目标镜像与实时原始字节门，拒绝时覆盖本轮空导出。六份 v2.2.1 实机归档显示全为已 arm、无 capture/stop 且点击闪退；无 `.ips` 崩溃指令证据。构建/实机状态见 `PROJECT_STATE.json`。
# v2.2.3 read-only descriptor evidence

将 v2.2.2 六游戏实机归档合并分析（Earn to Die Rogue 14/14 名称，六款均 0 patch）；对每个功能字典的子数组新增仅只读的选中镜像描述符字段、类型、实例字段偏移和有界标量导出；候选菜单增加 LC_UUID 与宿主版本信息；未添加任何 setter hook 或目标 getter 调用。状态见 `PROJECT_STATE.json`，需新的设备验证。
# v2.2.5-dev — cross-image evidence graph

- 分析 v2.2.3 七组实机日志：7 款、27 个按钮、0 canonical patch，统一拒绝原因为 `missing-offset`。
- 用菜单 UUID 精确关联 Earn to Die Rogue、Dragon Fever TD、Rise of Berk 三组二进制。
- 从 Objective-C 元数据和 arm64 getter 汇编确认三种菜单的 160-byte 描述符均以 `+0x48` 保存 offset wrapper、`+0x58` 保存 signature wrapper；明确它们不是游戏 RVA。
- 包装器方法证据不再要求实现必须位于已选菜单镜像；记录 wrapper class image、implementation image/path/UUID、相对 load base 地址，保持 `invoked=false`。
- 新增有界 raw ivar evidence；系统镜像对象不展开。
- 目标可执行镜像枚举上限从 512 对齐到 2048，并收紧 app bundle 路径边界。
- 新增 `tools/hfamap_log_matrix.py` 与测试；主机测试 14/14 通过。
- 修正 UI/诊断开发版本为 v2.2.5-dev；Linux/Theos arm64 编译、链接、strip、ldid 签名和二进制静态验收通过，尚未实机验证。

# v2.2.6-dev — pointer/decrypt evidence and canonical gate

- 解析 v2.2.5 七游戏实机归档：7/7 扫描完成、27 个按钮、0 canonical patch；Legacy/AP wrapper 的 `+0x10` 原生 secret 指针是此前未采集的直接断点。
- 读取 GitHub `zpatchig`、v1.9.30、v1.9.31、v1.9.33、v1.9.34、v1.9.37.10 历史证据；确认 v1.9.33 曾实机完成 runtime-record 3 功能/8 静态 patch。
- 新增 pointer ivar 的 `vm_read_overwrite` 有界证据和对象身份 token；不调用 wrapper `secret` getter，不写目标内存。
- 新增当前 wrapper 实现镜像 `__text` 唯一 ARM64 解密指纹扫描。仅当 `D105C3FF @ +0x00 / B9400408 @ +0x30 / 53187D00 @ +0x40` 唯一命中时，才对 secret blob 的 scratch copy 调用解密函数；禁止固定 `getter+0xD00` 和样本 RVA。
- 描述符按同容器关系关联 `+0x40 patch wrapper / +0x48 offset wrapper / target image`；类型被擦除时还要求 0xA0 实例大小和 selector fingerprint。
- 解密结果仍须通过唯一目标镜像、UUID、preferred Mach-O VM offset、可执行区间和 live original bytes；已启用状态、歧义和越界全部 fail closed。
- Jailpatch 新增 `C4M0Manager`、`loadConfig:`、`loadPolicies` 的 class/method IMP 跨镜像归属记录，不调用配置入口。
- 主机测试从 14 增至 18 项并全部通过；Linux/Theos arm64 两次 clean build 的最终 dylib 逐字节一致，SHA256 `6d1db12b39c304e2e38e9de31255950a6e3d528ebe772e54540a52aa08d9c721`。
- 尚未运行 v2.2.6 实机测试；当前状态是“已修改、已编译、未实机验证”。
# 2026-09-21 — Fuel/Boost menu-hook genericization analysis

- No runtime source code changed; no commit, CI, build or device run was performed.
- Inspected `libswift_Concurrency.dylib`, the iOSGods `1.28.251` deb, standalone/deb/game-package `EarntoDieRogue.dylib` variants, matching UnityFramework and metadata.
- Verified all three menu dylib variants share UUID `8FDF838E-005A-3298-85D2-10B6BAECD161` and byte-identical business `__text`.
- Recovered the Fuel/Boost hook callback at `0xB88D8C`: `Fuel -> +0xB8`, `Boost -> +0xBC`, value `9999999.0f`, then original tail-call.
- Recovered the hook-install call site at `0xB88E44`; the target is resolved dynamically from encoded/signature evidence rather than a plaintext Unity RVA.
- Cross-validated the field-flow algorithm against UnityFramework UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`; unique consumption sites match `0x2D98AC8` and `0x2D9887C` and expected original bytes.
- Added `HFAMap_v2.3.2_FuelBoost菜单通用化二进制分析.md`.

## 2026-09-21 — v2.3.4 `日志2(7)` six-game acceptance analysis

- Parsed input SHA256 `a582ca70bfcf99794b7067c65ad19c311dd7ec84eb18214024013775ab7624af`: 6 games, 19/19 complete sessions, 36 JSON, 12 JSONL and 1222 JSONL records, with no parse/error/failed/timeout event.
- Verified 22 Block provenance records were read-only and never canonical-eligible.
- Verified final outputs: Earn 14 groups / 20 patches; MeChat 4 / 6; XP Hero 1 / 1; Dragon/Path runtime-only; Whisper 2 missing-offset.
- Matched Dragon, Earn, Path and Whisper menu UUIDs to local binaries and disassembled their common owner Block; all call `_NSLog` with `@"iGMM Initialized"`.
- Disassembled Path `kButtonTapHandler` at `0x66B0`; recovered nested global Block invoke `0x66C4` and dynamic target calculation `image slide + 0x3DEC9A0`.
- Added `HFAMap_v2.3.4-dev_日志2(7)实机验收.md` and updated project state/roadmap/handoff/known issues/success history.
- Source code was not changed. No commit, CI, build or new device run was performed during this analysis.
