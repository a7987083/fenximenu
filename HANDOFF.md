# HFAMap Handoff

## 2026-09-22 v2.3.8-dev Dual Runtime Probe（开发中）

- 继续分支：`feature/hfamap-v2-bounded-universal-analyzer`；远端起点 `85a9b9bffd6db70f19a575caa0f3ff4ee7d667c4`，其 v2.1.1 rollback 历史不改写。
- 恢复基线：用户上传 v2.3.7 完整包；ZIP SHA256 `1f5e6734790b1cb968f4fbc8be43c65fe847af3923f4315afd77d1bb3eeb3f90`；基线 dylib SHA256 `06716ac60f7374ad8989928776f8487d8e1132fa992309ecda0a5f4d7c7e115f`。
- 新模块：`hfamap/src/HFAIL2CPPRuntimeProbe.mm/.h`。它是可逆、限量、analysis-only 的 resolver/invoke observer，不是 method caller。
- 可用门：目标进程必须可解析 `DobbyHook/DobbyDestroy` 及 `il2cpp_class_from_name`、`il2cpp_class_get_method_from_name`、`il2cpp_runtime_invoke`；不满足即 fail closed 并输出原因。
- 已知盲区：目标可能在 Arm 前缓存 MethodInfo，或直接调用 method pointer 绕过 `il2cpp_runtime_invoke`。0 event 不能证明不存在 runtime method。
- 首轮设备步骤：XP Hero Arm 后只触发 Currency 一次，等待自动 Stop；再 Arm 只触发 Exp 一次；保存两轮 RuntimeProbe/Diagnostics。Enemy Can't Attack 与 Fuel/Boost 不用于验证这条方法链。
- 实现提交 `54370834a2414a216a30cd97de86429126218b01`；Actions Run `35697312404` 全步骤成功；artifact `10681226081`。
- arm64 dylib：196608 bytes；UUID `7C045523-558F-38D0-B06B-5FF612C3EB43`；LC_CODE_SIGNATURE 3056 bytes；SHA256 `43e79104d484a010b99d7f92ee38a2ec56938b54288ac9f2f0752588362d4dd4`。
- 当前严格状态：已提交、已 CI 编译、未实机。下一证据门仍是 XP Hero 两轮单功能 Probe 与 hook restore=0。

## 2026-09-22 成功逻辑完整交付包

- 总索引：`HFAMap_SUCCESS_LOGIC_PACKAGE_README.md`。
- 包含 source/tests/tools、v2.3.7 dylib、所有开发/实机报告、长期状态文件、`日志2(10)` 六游戏证据和 XP Hero 专项证据。
- XP Hero 当前实机已解出第三项 `0x5083978 / F08B80D2 -> C0035FD6`。不要把 secret object 地址 `0xBC1588/0xBC15B0` 当游戏 patch RVA。
- `+0x397768` 是当前 Probe 看到的共享 UI action；用户提供的 `+0xB8B608/+0xB8BA50` 是待 matching artifact 验证的 inner runtime callbacks，两层不可互相覆盖。
- 当前源码不是 Git worktree；交付包不能提供有效 Branch/HEAD/Commit/Actions Run。

## 2026-09-22 v2.3.7 `日志2(10)` 六游戏设备状态（当前最高优先级）

- 输入归档 SHA256 `eef4f73327e517c8f8153bb938f2d1f58fecfff700fc842e9efed73d4dc19ff7`；6 款、12/12 Probe sessions、186 callbacks、88 logical records、12/12 restored、0 restore failure。
- Probe 生命周期与 slider 合并通过；Dragon 第二轮 99 samples 合并为一条 1→100 summary；无重复 Arm 闪退。
- 六款共 40 条 control/target/selector/IMP 入口证据，全部 `unresolved-action-sink`。不要将共享 action IMP 当 patch RVA。
- 四份 matching binary 已证明状态漏报根因：自定义 UIControl 有 `isOn/currentState` property，backing ivar 固定在 +56/+80，但名称混淆，v2.3.7 的 state-like ivar 名称过滤把它们排除。
- 下一版首要修改：解析 ObjC property attributes `T`/`V`，由已知 scalar property 定位 backing ivar，保留实例边界读取，禁止 KVC/未知 selector。
- MeChat/XP 缺 matching menu binary，同布局只能作为共同祖系推断，不能写成已证明。
- Canonical 仍为 27 patches；9 runtime-only、5 missing-offset。Fuel/Boost 仍由 menu callback field dataflow 得到，不是 Probe 生成。
- 完整报告：`HFAMap_v2.3.7-dev_日志2(10)实机验收.md`。本轮无代码/build/commit/CI。

## 2026-09-22 v2.3.7-dev State + Action Sink（当前源码/构建）

- 当前源码版本 `2.3.7-dev-state-action-sink`；当前目录不是 Git worktree，不能提供 Branch、HEAD 或 Commit。
- custom control 状态链位于 `HFAMapRuntimeProbe.mm`：只读 menu-local class primitive ivar，输出 Arm/immediate/settled 三阶段和差异；没有 KVC、未知 selector、对象 ivar解引用、IMP 替换或内存写入。
- action 入口链位于 `HFAMapResolver.mm`：Scan 捕获 exact control/target/selector/event，worker 解析 method IMP location 并复用 bounded ARM64 semantic classifier，输出 `actionProvenanceEvidence/actionSinkClass`。
- action provenance 只证明入口和有限 sink 类型，不等于 patch。必须继续闭环 target image/UUID、目标指令数据流、enabled 语义与 live original bytes。
- 62/62 tests；双 clean arm64 build identical；211344 bytes；UUID `66BB51DA-E19C-31AD-A170-A1EF955CE9A3`；SHA256 `06716ac60f7374ad8989928776f8487d8e1132fa992309ecda0a5f4d7c7e115f`；LC_CODE_SIGNATURE 2048 bytes。
- dylib：`hfamap/dist/v2.3.7-dev/HFAMapUniversal-v2.3.7-dev.dylib`。
- 完整交付包：`hfamap/dist/v2.3.7-dev/HFAMapUniversal-v2.3.7-dev-Complete-Delivery.zip`，SHA256 `ebdaf846f5585657862d6bbae01a4bcf0ec595c3164185a93783f39bafebaffd`。
- 未运行 Actions、未实机。设备基线仍是 v2.3.6 `日志2(9)`：6 款/12 sessions、180 callbacks、12/12 restored。
- 首轮实机优先：Whisper/MeChat/XP unresolved 按钮、Dragon slider、自定义开关双向切换、Path Debug Menu；每款至少两轮并检查 restore。

## 2026-09-22 v2.3.6 `日志2(9)` 设备状态（当前最高优先级）

- 最新设备基线：6 款、12/12 Probe sessions、180 callbacks、96 logical records、12/12 restored、0 restore failure、无重复 Arm 闪退。
- Slider coalescing 已实机通过：Dragon run1/run2 分别 39/47 samples，各占一个 logical slider record；Diagnostics 保留 raw samples。
- 自定义开关的 `registeredControlEvents=[value-changed]` 与 label/action/IMP 绑定稳定，但不是 UISwitch，`switchOn` 缺失、`selected=false`；不要写成 ON/OFF state 已验证。
- Path Debug Menu 为 touch-up-inside `+0x347DC4`；其他 Path control 为 value-changed `+0x3496F8`。
- Path block classifier 仍只得到 outer dispatch chain；nested `+0x66C4` imports 只有 objc_msgSend，dlsym fallback 未恢复 `0x3DEC9A0`。下一版必须先加 bounded resolver diagnostics，不要继续猜。
- Fuel/Boost 不是从 Probe action `+0x397098` 直接生成。真实链在 `HFAMapHookSemantic.mm`：exact identifier → menu callback `0xB88D8C` → fields `+0xB8/+0xBC` → target `ldr/fsub/str` → live original → NOP。源码无 Earn/RVA/UUID 硬编码。
- 完整报告：`HFAMap_v2.3.6-dev_日志2(9)实机验收.md`。
- 本轮仅文档更新；build/UUID/SHA 不变，无 Git commit、无 CI。

## 2026-09-21 v2.3.6-dev Interaction Probe（历史构建基线）

- 当前源码版本 `2.3.6-dev-interaction-probe`。v2.3.5 `日志2(8)` 是最新设备基线：6 款、12/12 Probe sessions、59 callbacks、12/12 target list restored、无闪退。
- Dragon 明确包含真实 slider：外层功能行 action `+0x34C7C8`，slider action `+0x34C7BC`，第一轮 15 slider samples。Path 的 Multiplier 本轮是自定义点击/值变化控件，不能按名称判 slider。
- `HFAMapRuntimeProbe` v2 为每个 menu action 保存 `registeredControlEvents`，并输出 `interactionKind`。slider 按 control token 合并 first/last/min/max/sample count；Diagnostics 仍记录原始 callback。
- 上限：768 views、128 controls、32 logical events、256 callbacks、2–15 秒。停止后反查 sidecar selector并输出 `targetRestoreFailureCount`。
- Path `+0x66C4` 实机只识别到 `objc_msgSend`，未得到 `0x3DEC9A0`。matching binary 证明指令链存在；v2.3.6 为 `dladdr` 缺 symbol name 增加 `dlsym` address fallback，仍待设备复验。
- 60/60 tests；双 clean release build identical；194752 bytes；UUID `CD334EBF-B188-3EBA-84B9-E744F6AE04DB`；SHA256 `60136b22a9d9969d63332ef5a343908a649ee1b097b3ad04bcae1ffc8ec5bda3`。
- 无 Git commit、无 CI；本段记录构建时状态，后续 `日志2(9)` 已完成部分实机验收。不得把 interaction evidence 升格为 static patch。
- 完整实机分析：`HFAMap_v2.3.5-dev_日志2(8)实机验收.md`。

## 2026-09-21 Legend 名字解析证据链审计

- `HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md` 第 8 项已加入 Legend 2.0.3 名字解析规则；旧第 8–14 项顺延。
- iOSGods 页面截图显示 16 个外部展示项；它只作为候选字典。真正绑定来自两轮实机 `same-feature-dictionary` registry：12 个 identifier/title records、16 个 descriptor/patch。
- 两轮 registry tuple SHA256 都是 `5641a97488f0a4cb0a848b2bf83d33f763a676c785b6c005922670bc54a667c7`；Canonical tuple SHA256 都是 `8843b0fdc148212729a96c260cb472640d12e6fb54cfffc7813de98908072251`。
- 内部 title UTF-8 byte lengths 为 `12,12,14,16,24,28,28,8,6,35,33,38`，与静态记录一致。注意 8 bytes 是 `Skill CD`，35 bytes 是 Patrol group；禁止按网页等长字符串硬配。
- 四个双 descriptor group 分别对应 Avatar/Frame、Patrol、Growth、Monthly 的组级语义；每组两个 descriptor 的逐项次序仍需更细的注册参数/目标语义才能绑定。
- 静态 VA `0xBBDD58..0xBBE688` 当前仅是已记录并由实机结构交叉支持，尚未用 UUID `F4A420C5-E116-3AE9-8943-C2D9E74F4CEC` 的本地 dylib 独立复算。

## 2026-09-21 v2.3.5-dev Runtime Probe（历史阶段）

- 当前源码版本 `2.3.5-dev-runtime-probe`。v2.3.4 六款/19-session 是运行时基线；v2.3.5 自身尚未实机。
- `HFAClassifyBlockInvoke` 最多读 96 bytes、跟随一层 nested global Block。公共初始化日志应输出 `nonsemantic-logging-block`；Path action 应输出 outer `runtime-action-dispatch-chain`，nested `runtime-action-target-resolved` 和 preferred RVA `0x3DEC9A0`。
- `HFAMapRuntimeProbe` 不替换任何原 IMP。它给已选 menu image 所属 target 的 UIControl 临时增加 sidecar target，观察用户自己的 TouchUpInside/ValueChanged，然后按 deadline/event limit/manual stop 撤销。
- 必须先 Scan，Core 才保存 policy-selected candidate；Probe 输出绑定 menu UUID、host bundle/version/build。不要退回按文件名猜版本。
- MRC 生命周期：controls/records/candidate/completion 均显式 copy/alloc/release；generation 阻止旧 deadline 停止新一轮 probe。
- 58/58 tests；双 clean build identical；194704 bytes；UUID `15DB159C-84E3-35E3-81E9-40051A8F1A94`；SHA256 `7712d07d6ada6c1bb87d0f3f5742d96b692ff554198bedbe0e37b91d7c8c2e59`。
- 无 Git commit、无 CI、未实机。首测必须做两轮 arm/stop，检查 `targetListRestored=true`、事件不重复和第二轮不闪退。

## 2026-09-21 v2.3.4-dev Block Provenance Probe

- 当前版本 `2.3.4-dev-block-provenance`；核心修改在 `HFAMapResolver.mm`，输出接线在 `HFAMapCore.mm`。
- Whisper matching artifacts：菜单 SHA256 `3d5ed747e18d637c1002520db0348084c0724f5702b88d61f1d262cd7500fcce` / UUID `08DAECF4-4F03-3F6D-BCE3-7E18112145AD`；UnityFramework SHA256 `0922078ede48b376d363cbe24c77e57b3274b8768e64230534e1ca9d6f9f0b0c` / UUID `93D606C9-6CFB-3DC0-BDCE-85A82455EFC9`；metadata SHA256 `355a09cf6d781f428349ee33270a475058ef39ea9f0e289e533dc2561e352e0a`、version 31。
- `日志2(6)` 的 `gIlPAd` owner 有 `GkfBZUYACywbRI -> __NSGlobalBlock__`，这是本版运行时要验证的首个对象；不要把字段名或预期 invoke RVA硬编码进 resolver。
- Probe 读取标准 Block header 的 isa/flags/reserved/invoke/descriptor，要求 invoke 4-byte aligned，并通过 dladdr/dyld 获取 implementation image、UUID 和 load-base RVA；菜单内 invoke 才读 32-byte instruction prefix。
- `blockProvenanceEvidence` 只证明 handler 入口，不证明 identifier 与该 handler 的一一映射，更不证明目标 patch。下一版必须用实机 RVA 回到 matching menu binary 做汇编、xref、分支与调用链分析。
- 53/53 tests；双 clean arm64 build byte-identical；176960 bytes；UUID `00790D66-05CE-363D-91CC-8244A0EC300E`；SHA256 `9938e35952181567d8b4fd3a000c43d8dc5585f4c9993f8043dc573ebc82f6ef`。
- 交付：`hfamap/dist/v2.3.4-dev/HFAMapUniversal-v2.3.4-dev.dylib`。无 Git commit、无 CI、未实机。

## 2026-09-21 v2.3.3 `日志2(6)` 部分实机验收

- 归档 SHA256 `734e9259b3739853aa344350eecd56d521d4b5c43fc1e3f3d139c888b7a4ccd1`；5 款、8/8 sessions complete、614 JSONL records、无结构化 hard error。
- Earn 两轮均完整覆盖：eligible/complete segments 7/7，eligible/attempted/scanned bytes 均为 129974272，failed/truncated 为 0，deadline/candidate cap 为 false。
- 两轮 Fuel/Boost 均 resolved，14 groups / 20 patches / 0 unresolved / 0 rejected；所有菜单字段、callback、target UUID、load/patch/store RVA 和字节与 v2.3.2 四轮完全相同。
- Dragon 5、Path 4 继续保持 runtime-only；MeChat 4 groups / 6 patches + 1 unresolved；Whisper 2 unresolved，没有错误提升。
- v2.3.3 正常 coverage success path 可以标记 device pass；整个 v2.3.3 验收不能关闭，因为 Earn 仅 2/5，未做 incomplete coverage 故障注入，也未验证 Fuel/Boost 实际启停。
- 第二次 Scan Menu 在 Dragon、Earn、Path 均完成，未复现闪退。
- 本轮仅文档更新；dylib 仍为 SHA256 `f63a7474c5c6f51a1d9921048e0db150b70f5e6a961f8503d312f7e6be90e801`，没有重编译、Commit 或 CI。
- 完整报告：`HFAMap_v2.3.3-dev_日志2(6)实机验收.md`。

## 2026-09-21 v2.3.3-dev Semantic Coverage Gate

- 当前源码版本为 `2.3.3-dev-semantic-coverage-gate`。核心改动位于 `hfamap/src/HFAMapHookSemantic.mm`，不要移除 v2.3.2 的 same-callback peer-field consensus。
- 新硬门：所有 eligible app executable segments 必须完整读取；任何 read failure、per-segment/global cap、deadline、candidate cap 或 bytes mismatch 都令 `scanCoverage.complete=false`。
- 不完整覆盖时状态为 `target-scan-incomplete`，保留候选和覆盖诊断但不生成 canonical patch。最终 deadline 跨越还会撤回先前暂存结果，避免 `status=timeout` 与 features 非空并存。
- `fields.empty()` 仍允许分析流程正常完成，因为此时没有 hook-semantic 候选需要证明；一旦存在字段，必须至少有一个 eligible target segment。
- 50/50 tests；两次 clean arm64 build byte-identical；176960 bytes；UUID `FF1F1171-6081-3E20-80A8-01C1F74BE1E7`；SHA256 `f63a7474c5c6f51a1d9921048e0db150b70f5e6a961f8503d312f7e6be90e801`。
- 交付 dylib：`hfamap/dist/v2.3.3-dev/HFAMapUniversal-v2.3.3-dev.dylib`。当前源码不是 Git worktree，无 commit、无 CI、无实机。
- 实机首验必须同时核对 `scanCoverage.complete=true`、`failedChunks=0`、`truncatedSegments=0`、`candidateLimitHit=false`、`deadlineExceeded=false`，再比较 Fuel/Boost tuple；不能只看最终按钮数量。
- v2.3.2 `日志2(5)` 的四轮 Earn 14 groups / 20 patches 是最近运行时稳定基线；v2.3.3 只能标记“已修改、已测试、已编译”。

## 2026-09-21 v2.3.2 `日志2(5)` 实机验收

- 输入 `日志2(5).zip` SHA256 `8ad0e70742992fce5a64a24583f437c7b7c015083d20d59cd9e89ee7afd25c57`；72 JSON、24 JSONL / 1709 records 全部解析成功。
- 12 款共 23/23 sessions complete，无 timeout/error/failed；诊断版本全部为 `2.3.2-dev-menu-hook-semantic`。
- Earn 四轮 session 耗时 970.253/622.383/593.175/599.959 ms，均为 14 registry、20 validated、0 unresolved、2 hook-semantic validated。
- Fuel/Boost 四轮 tuple-set SHA256 均为 `04fc642c9c2bfd21951b9c8ba0ec36cc5483075afdfd2dd0ecce5fb99e598675`；最终 Canonical 为 14 groups / 20 patches。
- Fuel：`Fuel -> +0xB8 -> UnityFramework+0x2D98AC8`, `0038211E -> 1F2003D5`；Boost：`Boost -> +0xBC -> +0x2D9887C`, `0038281E -> 1F2003D5`。地址语义是 preferred Mach-O VM RVA；target UUID 四轮均为 `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`。
- 新链保持只读：`memoryWritten=false`、`selectorInvoked=false`、`hookInstalled=false`。
- 其他游戏 final 合计 43 groups / 62 static patches / 9 runtime-only / 12 unresolved；所有 sidecar complete、0 rejected。
- 不要把扫描成功误写成补丁功能启停成功；归档没有 Fuel/Boost 实际消耗与关闭恢复证据。
- 本轮只更新报告/状态，无代码改动、无新 build、无 Commit、无 CI。完整报告：`HFAMap_v2.3.2-dev_日志2(5)实机验收.md`。

## 2026-09-21 v2.3.2-dev Menu Hook Semantic Resolver

- 当前源码已新增 `HFAMapHookSemantic.mm/.h` 并接入 Resolver/Core/Makefile；版本为 `2.3.2-dev-menu-hook-semantic`。
- 菜单侧从当前 registry identifier 的 exact cstring/CFString 引用恢复 callback 内字段写入；目标侧扫描当前 app executable segments 的同字段 `ldr/fsub/str` 数据流。
- Fuel 的 `+0xB8` 全段原始候选数是 2，不是 1；Boost `+0xBC` 为 1。同一个菜单 callback 的多字段共识门要求同 target image、同 base register、RVA 距离不超过 0x8000，使 Fuel/Boost 均收敛到正确唯一候选。
- 不要删除该共识门，也不要把 `0x2D98AC8/0x2D9887C`、Earn bundle 或 Unity UUID加入 resolver 输入；它们只能作为离线验收真值。
- Resolver feature 判重已带 identifier，符合“同按钮完全重复去重、跨按钮共享 offset/patch 保留”的规则。
- 安全合同：只读；无 selector invocation、无 Hook、无 memory write；零/多候选继续 unresolved。
- 验证：47/47 tests；双 clean Linux/Theos arm64 build byte-identical；176960 bytes；UUID `FBE89C72-1C29-384A-984A-6E5C8D33A1B7`；SHA256 `5344dde8f5aa39ba822443608bfd3dcde7144dcdfafeb1853fc2c25acaf5048b`。
- 当前源码不是 Git worktree；无 commit、无 CI、无实机。下一步必须先做 Earn 五轮扫描与 Fuel/Boost 独立启停，不能把离线通过写成实机成功。
- 长期报告 `HFAMap_OFFSET_PATCH_SUCCESS_HISTORY.md` 是强制维护项；以后 offset/patch 链的每次成功、失败边界或真值门变化都要同步更新。

## 2026-09-21 v1.9.37.10 Fuel/Boost 通用化评估

- GitHub 私有仓库真实分支：`feature/hfamap-v193710-unified-feature-model`，HEAD `9fe759fe8519bfcaa90c2461a256c18a4d6c2080`；实际实现 Commit `13fff6fd49d84348c618cc7845527e0b5c8413fa`。
- Actions Run `35170319783` 在 build commit `5db1f384c49a4a4cd243b722881083f0893692e5` 成功完成 profile 校验、Theos compile/link/sign 和 artifact upload。v1.9.37.11 分支主要增加 release promotion/CI marker 加固，Fuel/Boost profile 本身已在 v1.9.37.10。
- 历史实现 `HFAAppendVerifiedEarnToDieRogueProfile` 是硬编码 exact-build fallback，不是从菜单推导 offset：固定 bundle/version/build、UnityFramework UUID、两个 RVA/original/enabled，并在 live original gate 通过后追加 feature。
- 历史文档证明 14 个按钮共享同一菜单 action，设备只发现 12 个 definition；因此仅靠菜单对象无法推出 Fuel/Boost RVA。通用化必须保留离线二进制/metadata 补证环节。
- 当前 v2.3.1 实机 registry 已稳定观察到 `identifier=Fuel/Boost`、正确 title、`canonicalEligible=false`、空 descriptorEvidence；这为 profile 与真实已加载按钮之间提供了可靠锚点。
- 推荐抽象：Menu-Anchored Verified Profile Bridge。代码通用、profile 数据按 exact build 维护；只为当前 registry 中的 unresolved identifier 补全，并继续要求 target UUID、executable range、live original bytes。
- 现有 `tests/earntodie_rogue_1.28.251_verified_profile.json` 已包含完整 schema 和证据，可作为首个 fixture；当前 v2.3.1 尚未加载它。
- 对 Earn 1.28.251 (1) 可预期从 12 groups / 18 patches 补到 14 groups / 20 patches，但 Fuel/Boost 的实际启停效果在历史文档中仍是 device runtime pending，集成后必须独立实机验证。
- 完整报告：`HFAMap_v2.3.1_VerifiedProfile通用化评估.md`。

## 2026-09-21 Earn v2.3.1 共享 offset 实机通过

- 输入 `新建文件夹.zip`，SHA256 `80209a042564ebe31f3b996d14039af784897123ea6aefa2e78ba9e8952b6989`；9 members CRC 通过，6 JSON + 2 JSONL / 688 records 全部解析成功。
- 五个 session 均加载 `2.3.1-dev-shared-offset-export`，同进程连续执行，5/5 complete；耗时 569.56–646.31 ms。第二至第五次扫描无闪退。
- 每轮 resolver：18 validated、2 unresolved；未解析项仍为 Unlimited Fuel/Boost 的 `missing-offset`。
- 每轮 Patch v1：12 feature groups、1 target、1 shared site、0 rejected。五轮 18 个完整 tuple 的排序 SHA256 均为 `1e00aefc88c6d2b437efb27743e58e58489692a87315263c2add289cc8eb1f41`。
- 最终 Canonical：schema `com.hfa.patch/v1`，bundle `com.notdoppler.earntodierogue` 1.28.251 (1)，architecture `arm64e`，12 groups / 18 patches，target `UnityFramework`。
- Sidecar：18 input / 18 emitted / 0 deduplicated / 0 rejected / 1 shared site。Posters 与 Prestige 同为 `0x2E25904`，relation `same-offset`，overlapLength 4。
- v2.3.1 的跨 feature 共享 offset 保留、同 feature 去重边界和二次扫描稳定性均已取得实机正证据。stale-output 故障注入仍未验证。
- 本轮无源码修改、无新 build、无 Commit、无 CI。下一任务只剩 stale-output 故障注入及 Git/Actions 固化。
- 完整报告：`HFAMap_v2.3.1-dev_Earn共享Offset实机验收.md`。

## 2026-09-21 `日志2(4).zip` v2.3.1 部分实机验收

- 输入 SHA256：`8b3d613ee5529415f038e07f8090b530b1a3b56294c2e429fc51d51efbe13e81`；ZIP 116 members，CRC 全通过。Info-ZIP 因 Windows Unicode local/central filename 编码差异报警，但 76 个 JSON 和 26 个 JSONL、共 858 条 JSONL records 全部解析成功。
- 13 款游戏各一个完整 session。Archery、Backpack、Dragon、Heavenfall、Hello Kitty、Legend、MeChat、Path、Pop Island、Rise、Whisper、Zombie 共 12 款加载 `2.3.1-dev-shared-offset-export`，12/12 complete。
- 12 款 v2.3.1 合计：30 个 Patch v1 feature groups、43 条静态 patch、9 条 runtime-only、12 条 unresolved；12 个 Canonical/sidecar 均生成，sidecar 全为 complete，0 rejected、0 deduplicated、0 shared（这些样本本身无跨 feature overlap）。
- 稳定回归：Rise 3 groups / 8 patches；Backpack 1；Zombie 2 groups / 4 patches；Dragon 5 runtime-only；Path 4 runtime-only。
- 新增正结果：Hello Kitty 5 patches；Legend 12 groups / 16 patches；MeChat 4 groups / 6 patches；Pop Island 1 patch。Whisper 2 项仍为 missing-offset。
- Earn 是唯一版本错误：日志明确为 `2.3.0-dev-jailpatch-target-resolution`，并报旧 `conflicting-patches-for-target-offset`；没有 Canonical/sidecar。不能据此判断 v2.3.1 失败。
- Earn 的 18 条 Patches 证据离线套用当前算法：12 groups、18 emitted、0 dedup、0 inconsistent-original、1 shared site；Posters/Prestige 在 `UnityFramework+0x2E25904` 重叠 4 bytes 且 original 一致。
- 本轮无需修改源码或重编译。唯一 Next Task：在 Earn 替换并校验 v2.3.1 dylib，确认诊断版本后连扫五次，再验证 Canonical 12/18 和 sidecar 共享位点。
- 完整报告：`HFAMap_v2.3.1-dev_日志2(4)实机分析.md`。

## 2026-09-20 v2.3.1-dev 共享 offset 导出实现

- 当前目录不是 Git worktree；没有 branch/HEAD/commit。状态严格为：已修改、38/38 测试通过、已双 clean build、未提交、未 CI、未实机。
- 交付 dylib：`dist/v2.3.1-dev/HFAMapUniversal-v2.3.1-dev.dylib`，arm64 Mach-O，142288 bytes，UUID `2273787C-2568-332F-9052-78D3192F6741`，SHA256 `5a693b5570e5e3a767e7873579f6f3a3c29b1a4361ff897b472ec8c82cd22d9d`。
- `HFAMapPatchV1.mm` 不再维护全局 `target:offset` signature。所有 byte-validated 记录先按 target/range 做 original overlap 逐字节一致性校验；不一致的相关记录进入 `rejectedRecords`，其余继续导出。
- 去重仅位于同一个 `identifier+title` feature group 内，key 为 `target+offset+enabled`。不同按钮即使 offset/patch 完全相同也分别保留。
- 跨 feature 的相同 offset 或部分重叠 range 生成 `sharedPatchSites`；Patch v1 本体保持原 schema，不塞入私有字段。旁路文件为 `Canonical.shared-sites.json`，schema `com.hfa.patch-export-report/v1`。
- `HFAMapCore.mm` 继续用 `NSDataWritingAtomic`；package 构建、Canonical 写入或 sidecar 写入失败时会移除对应旧文件，修复 stale-output 风险。
- `.github/workflows/theos-hfamap-v2-bounded-universal.yml` 已更新为完整 tests discovery 和 v2.3.1 精确 artifact 名，但因为源码快照没有 `.git`，尚未实际触发 Actions。
- 下一任务：Earn 连扫五次，验证 18 条 patch、Posters/Prestige 同 offset 共存和 sidecar；再回归 Rise/Backpack/Zombie 与陈旧文件清理。完整开发报告：`HFAMap_v2.3.1-dev_共享Offset导出与交付.md`。

## 2026-09-20 v2.3.0 实机验收与新阻塞

- 输入 `日志2(3).zip`，SHA256 `2b31ba45527d117f02aa64ac74cbb94dcc08eeb0efe9ac0fbd84f0e1963ae180`。
- 8 款 41/41 sessions complete；每款五次，Dragon 六次。v2.3.0 重复扫描和目标归属实机通过。
- Rise：五轮均为 3 features / 8 patches；40/40 target resolution unique，target `Dragons-prod-remote-nocheat`，UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`；8 条 original/enabled tuple 完全一致。
- Backpack：1 patch；Zombie：4 patches；Earn：18 validated patches。裸十六进制解析修复取得跨家族实机正结果。
- Dragon/Path runtime records 与 v2.2.9 归一化内容完全相同；Rise 已从 3 runtimePrimitive 转为 8 个真正 static patches。
- Earn Patch v1 被当前全局 slot 规则拒绝：Posters 与 Prestige 同起点 `0x2E25904`，分别写 4/8 bytes 且 enabled 不同。用户确认原菜单允许多个按钮共享同一 offset，因此解析器下一版应保留两个 feature；运行时相互影响只作为旁路元数据，不应导致整包丢失。
- 最高优先级代码风险：`HFAMapCore.mm` 的 v1 rejected 分支只记日志，不删除旧 `Canonical.hfapatch.json`；非干净 Documents 环境可能遗留陈旧包。
- v2.3.1 应将去重限制在同一 feature 内，跨 feature 的共享 offset/range 原样导出；只有 overlap original 自相矛盾才拒绝相关证据。同时加入旧文件清理/原子替换和结构化 shared-site report。
- 日志注入路径名仍写 v2.2.9，但 dylib UUID `438D21D8-266A-3AEE-AD80-A0CA1A07479F` 与 v2.3.0 交付一致，诊断版本也是 v2.3.0；只是部署文件名未改。
- 本轮没有代码修改或新 build。完整报告：`HFAMap_v2.3.0-dev_实机验证与冲突分析.md`。

## v2.3.0-dev 当前交接（最高优先级）

- 当前目录不是 Git worktree；没有 branch/HEAD/commit。远程私有仓库需要认证。当前状态：已修改、35/35 测试通过、已双 clean build、未提交、未 CI、未实机。
- 交付 dylib：`dist/v2.3.0-dev/HFAMapUniversal-v2.3.0-dev.dylib`，arm64，141968 bytes，SHA256 `de588af615e7e96058520d0432135992e52b484302d76e3fb4fe52201e41b3cb`。
- 根因一：解密 offset 是十六进制，但旧 `HFAOffsetValue(base=0)` 会拒绝裸 `A–F` 值，并把裸纯数字值当十进制。
- 根因二：Rise descriptor 没有 target image 字符串，旧路径不会按 offset 对 executable range 做唯一映射。
- 新链：`scratch-copy decrypt -> HFADecodedOffsetValue(base16) -> unique executable preferred-range -> UUID/range -> live original read -> canonical`。
- `HFAOffsetValue` 保持不变；只有已经通过 decrypt fingerprint/scratch-copy gate 的明文进入新解析器。
- `HFAExecutableImageResolutionForDecoded` 只接受唯一命中；零/多命中、无效 patch 和跨边界均拒绝。显式 target 字符串不被推断覆盖。
- 仍然没有 selector invocation、Hook、`method_setImplementation`、`method_invoke` 或 `vm_write`。
- 下一任务只做实机验收：Rise 连扫四次，要求 target resolution 为 unique、3 features / 8 patches、live originals 存在且四轮 tuple 一致；再检查 Dragon/Path runtime-only 无回归。
- 完整报告：`HFAMap_v2.3.0-dev_目标镜像归属与交付.md`。

## 2026-09-20 v2.2.9 实机验收

- 新输入：`日志2(2).zip`，SHA256 `53fbb1382b0a410398722b0b737a7e6398202ac8049a4cfab625c2bd9397096e`。
- 8 款游戏、37 次同进程连续扫描全部完成；每款 4–5 次，0 incomplete。第二次点击闪退未复现。
- v2.2.9 `RuntimeActions.json` 已实机验证：Dragon 5、Path 4、Rise 3。Legacy Patch v1 仍为 17 条且与 v2.2.8 完全一致。
- Dragon owner inventory：`C4M0Manager` 23 methods / 18 candidates；`loadConfig:` 位于 iGameGod UUID `382058D1-2B4E-3AF9-B77D-054A76AB7FD9` + `0x3C776C`，`loadPolicies` 位于 `+0x3C79B0`。不要调用或 Hook。
- Path/Rise 的 owner method inventory 为空，但 `policies` ivar 均为 instance offset `0x8`；ivar offset 不是 patch RVA。
- Rise 的菜单解密已成功：四次都得到 3 features / 8 offset+enabled pairs。8 个地址唯一位于主程序 `Dragons-prod-remote-nocheat` preferred executable range；当前代码只从 descriptor 字符串推 target image，因此卡在 `targetImage=unresolved`。
- 接手后首个代码任务：在 `HFAReadOnlyDescriptorEvidence` 解密成功但 target 缺失时，对 `execImages` 做 offset range 唯一映射；然后复用 `HFACanonicalPatchFromDecoded` 获取 live original。零/多命中、越界、读失败、patch 已启用都必须 fail closed。
- 完整证据表见 `HFAMap_v2.2.9-dev_实机验证与v2.3.0入口.md`。
- 本轮没有代码修改、没有新 build、没有 CI；当前 dylib 仍是 v2.2.9-dev SHA256 `676f3ae3536637fdb3b215ce434c16f9e00c60891048970294a3b6d03655aa36`。

## v2.2.9-dev 上一交接（历史基线）

当前目录不是 Git worktree。`git status/branch/rev-parse` 均不可用；远程 `a7987083/fenximenu` 需要认证。因此本地修改状态为“已修改、已测试、已编译、已实机验证、未提交、未 CI”。不得伪造 commit 或 Actions 状态。

### 稳定输入与运行证据

- v2.2.8 基线 dylib：108576 bytes，SHA256 `e5ab1eaf03bc91bdaa709f080cd1730f07549f97475d54b3730bd2f8a98020cb`。
- 新日志：`日志2(1).zip`，SHA256 `f14c31109da24bfb8ba5b71d64af5bd64820fa4e939dc4b6c9e8f7cb38237833`。
- v2.2.8：8/8 单次扫描完成，31 个 registry 项，17 条 byte-validated canonical patch，19 条非 canonical 记录。
- Patch v1：八款均生成合法文件；非空结果为 Archery 1、Earn 15、Heavenfall 1。
- 新增 Path of Kings：`libpathofkings.dylib` UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`，Jailpatch，4 个功能，0 static patch。
- v2.2.9 连续扫描修复已实机验证：8 款每款 4–5 次，共 37/37 个完整 session；旧 v2.2.8 单次日志只保留为历史基线。

### v2.2.9 调用链

`Scan Menu -> loaded-image selection -> main-thread UI target snapshot -> worker container traversal -> HFARegistryRecord -> HFARuntimeSemantic/HFAValidatedFeature -> static Patches + RuntimeActions + Analysis/Registry/Diagnostics`

Legacy/AP canonical 链保持不变：

`feature dictionary -> descriptor array -> 0xA0 descriptor -> +0x40 patch wrapper/+0x48 offset wrapper -> unique pointer ivar -> bounded secret blob -> unique current-image ARM64 decrypt fingerprint -> scratch-copy decrypt -> target image/UUID/preferred VM/executable range/live original bytes -> canonical feature -> Patch v1`

Jailpatch/iGMM 新链：

`feature dictionary(label/identifier/type/default/handler presence) -> runtimeValue/runtimeToggle/runtimeAction -> analysisOnly RuntimeActions.json`

并行 owner evidence：

`objc_getClass(C4M0Manager) -> bounded instance/metaclass method inventory -> selector/ABI/declaring class -> IMP image/path/UUID/RVA -> scored candidates + ivar/property metadata`

该链明确不发送 selector、不调用 getter、不 Hook、不写目标内存。运行时 record 不进入 `com.hfa.patch/v1`。

### 当前构建

- 版本：`2.2.9-dev-jailpatch-runtime-evidence`。
- 测试：31/31 pass。
- 构建：Linux/Theos iPhoneOS 16.5 SDK，arm64 iOS 12.0 target；两次 clean build 相同。
- dylib：140464 bytes。
- SHA256：`676f3ae3536637fdb3b215ce434c16f9e00c60891048970294a3b6d03655aa36`。
- CI：not run。
- device：passed，8 款 37/37 sessions complete；RuntimeActions 12 records；静态 Patch v1 17 条无回归。

### 下一位工程师的唯一 Next Task

开发 v2.3.0 的 `unique-offset-range` target resolver：Rise descriptor 已稳定解出 8 组 offset+enabled bytes，但没有 target 字符串。只在解密 offset 唯一落入一个当前 executable preferred-VM range 时选定目标，并继续要求 UUID、可执行范围和 live original bytes。先以 Rise 验证 3 features / 8 patches；Dragon/Path 不进入 Hook。

完整历史成功逻辑和失败分叉见 `HFAMap_v2.2.9-dev_成功逻辑与运行时证据.md`。

## v2.2.0 local development state

The selected-image descriptor observer is implemented locally and is not stored in the GitHub repository. Workflow: open the original menu, run the bounded scan, arm capture for 20 seconds, toggle original menu controls, then stop/export. Review `HFAMap_DescriptorCapture.json`, `HFAMap_Diagnostics.jsonl`, and `HFAMap_Diagnostics.log` together.

The implementation compiled, linked, stripped and signed on GitHub Actions Run `35431604227`, commit `ec0621c4566774d2bf0346e59e6c48a2f23a9c26`, Artifact ID `10580433810`. The extracted v2.2.0 binary is 93,088 bytes with SHA-256 `f64244d826c7862814e53b4f783d376c889bba65fdf0daa1a8bd56122cb731e1`. It has not been injected or device-validated. Do not treat observed setter values as canonical offsets/patches until the existing target-image mapping and byte truth gates pass.

The original Actions artifact accidentally included old `hfamap/dist/*.dylib` files because of a broad upload glob. The separately delivered v2.2.0 package contains only the v2.2.0 dylib and its metadata. Future workflows should upload only the exact output path.

No target app Info.plist was provided. The build generated a fallback Info.plist with `CFBundleExecutable=HFAMapUniversal`, so the compiled output is named `HFAMapUniversal_HFAMapUniversal_v2.2.0_DescriptorObserver.dylib`. A target app's `CFBundleDisplayName` can only be embedded in its build filename after its real Info.plist is supplied.

## v2.1.0 first-pass implementation

Active branch: `feature/hfamap-v2-bounded-universal-analyzer`.

The first-pass implementation now uses a 350 ms main-thread UI/target snapshot and performs descriptor traversal on the serial worker queue. It records Objective-C class-count evidence and the stable 160-byte descriptor signature, and writes live session diagnostics to `HFAMap_Diagnostics.jsonl` plus `HFAMap_Diagnostics.log`.

Local verification: Python unit tests 4/4 passed; the supplied archive classified all 11 dylibs into the expected Legacy AP/Jailpatch families. GitHub Actions run `35403381939` passed compile/link/sign for remote commit `3ad558978f8bd648fefa737bd80f6c5596507426`. Artifact ID `10570699914`; dylib SHA-256 `5903e172814bf9950ceceb55440adeff1747deffb2cbecec8755017517db6246`. Device verification is still required.

## Active work

- repository: `a7987083/fenximenu`;
- branch: `feature/hfamap-v193710-unified-feature-model`;
- product version: `v1.9.37.10 UnifiedFeatureModel`;
- previous build commit: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`;
- verified-profile implementation: `13fff6fd49d84348c618cc7845527e0b5c8413fa`.

## Earn to Die Rogue conclusion

Target identity:

```text
bundle       com.notdoppler.earntodierogue
version      1.28.251
build        1
architecture arm64
image        UnityFramework
UUID         8654D76C-B760-34FC-BEE0-FE70AE8C95C8
```

Missing canonical patches:

```text
Fuel  UnityFramework+0x2D98AC8  0038211E -> 1F2003D5
Boost UnityFramework+0x2D9887C  0038281E -> 1F2003D5
```

Both sites belong to `Assembly-CSharp.dll!com.notdoppler.ETDR.Car.FixedUpdate()`
at RVA `0x2D9827C`. Fuel is `_fuelAmount` at object offset `0xB8`; Boost is
`_boostAmount` at `0xBC`. The original instructions subtract per-frame
consumption and the replacement is one ARM64 `nop`.

The original v1.9.37.10 result was incomplete because the shared Objective-C
action (`AaNfXa -ddktmnuyvBoEK:`, `EarntoDieRogue.dylib+0x397098`) was treated
as evidence of a runtime-only implementation. All 14 controls share that menu
dispatcher, including the 12 already-proven static features, so that inference
was invalid. The exact-build profile repairs Fuel/Boost without weakening the
generic truth gates.

Implementation files:

- `.github/scripts/hfamap_v193710_earntodie_verified_profile.py`;
- `.github/workflows/theos-hfamap-v193710-unified-feature-model.yml`;
- `tests/earntodie_rogue_1.28.251_verified_profile.json`;
- `docs/EARN_TO_DIE_ROGUE_1.28.251_ANALYSIS.md`.

Runtime acceptance requires bundle/version/build, arm64, exact UnityFramework
UUID and both original-byte checks. No address is reused on another build.

## Verification boundary

Static verification, the complete local generation chain and GitHub Actions
compile/link/sign passed. Build run `35170319783` produced artifact
`10476488771`; the downloaded arm64 dylib is 247824 bytes with SHA-256
`afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`.
Device enable/disable regression remains pending. Enabling the patch stops
further depletion but does not refill a value that was already zero.

The pre-existing package also has an unresolved overlap at
`UnityFramework+0x2E25904`: Posters writes `08E0BF12`, while Prestige writes
`20008052C0035FD6`. Resolve or explicitly arbitrate that conflict before calling
the full 14-button package conflict-free.

## Current branch

`feature/hfamap-v19361-json-export`

## Current direction

HFAMapUniversal is a **parser/exporter only**:

`original menu -> parser -> evidence -> normalized JSON`

The runtime-consumer/Dobby merge from v1.9.37 and v1.9.37.1 is retired after both builds crashed on device injection. The frozen parser baseline is v1.9.36 ArchitectureTruth commit `75f94da37221343b6839465ad365ddec2679e63a`. JSONExport versions must preserve the v1.9.36 constructor, `run_full_scan()` and resolver core.

## Current build: v1.9.36.4 JSONExport

- Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`.
- GitHub Actions run: `34907671999` — success.
- Artifact: `HFAMapUniversal-v1.9.36.4-JSONExport` (ID `10372928333`).
- Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`.
- Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`.
- Architecture: arm64 Mach-O dylib, NOUNDEFS.
- Size: `192432` bytes.
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

## WayOfKings / iGMM device validation: PASSED

Device archive `归档 6(1).zip` confirms v1.9.36.4 itself on device:

- injection stayed stable; no startup crash;
- Full Scan reached completion;
- `com.hfa.igmm.runtime/v1` regenerated;
- `com.hfa.menu.analysis/v1` regenerated;
- `IGMM-RUNTIME-EXPORT` reported `features=4`;
- `JSON-EXPORT` reported `status=pass features=4 sources=1 targetIdentities=2`.

Normalized controls:

- `Damage Multiplier`: `number`, default `1`;
- `Defence Multiplier`: `number`, default `1`;
- `God Mode`: `toggle`;
- `Debug Menu`: source `kTypeButton` -> normalized `button`.

Evidence-preserving primitive/reason handling is now device-confirmed:

- Debug Menu raw `executionPrimitive = nativeHook` remains visible;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction`;
- Debug Menu raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains visible;
- Debug Menu `normalizedCanonicalReason = runtime-action-not-static-bytes`.

Other normalized reasons also remain consistent:

- Damage / Defence -> `dynamic-numeric-state-not-static-bytes`;
- God Mode -> `runtime-hook-requires-portable-equivalent`.

Target identities remain correct on device:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`.

Observed implementation evidence remains diagnostic only:

- Damage/Defence/God share handler evidence around `libpathofkings.dylib + 0x4128`, with trampoline evidence toward `UnityFramework + 0x3BF6D94`;
- Debug Menu has `buttonBlock` evidence at `libpathofkings.dylib + 0x66B0`, nested handler `+0x66C4`, resolving to `UnityFramework + 0x3DEC9A0`.

## Output contract

Normal scan outputs may include:

- `HFAMap_Learn.log`
- `HFAMap_MenuMap.jsonl`
- `HFAMap_JailpatchMap.jsonl`
- canonical `*.hfapatch.json` only when true static byte patches are proven
- `*.hfapatch.identity.json` for canonical identity when available
- `*.hfamap.igmm.json` for iGMM runtime diagnostics
- `*.hfamap.analysis.json` for normalized analysis-only descriptions

The normalized schema remains `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Next validation

WayOfKings tuning is complete for this parser line. Do not keep changing the iGMM normalizer without new contradictory evidence.

Next use the **same v1.9.36.4 dylib** for cross-family regression:

1. runtime-record/static 5 MB family: require correct canonical `com.hfa.patch/v1`, target identity, preferred VM offsets, and original-byte truth;
2. legacy ~15 MB family: require the historical static patch path to remain functional;
3. compare normalized analysis output across all three families.

## Verification discipline

- v1.9.36 parser baseline: frozen/reference.
- v1.9.36.1 WayOfKings startup/scan/export: passed.
- v1.9.36.3 WayOfKings controls/target identities: device passed.
- v1.9.36.4 compile/link/sign: passed.
- v1.9.36.4 CI: passed on run `34907671999`.
- v1.9.36.4 artifact re-hash: passed.
- v1.9.36.4 WayOfKings device validation: **passed**.
- runtime-record/static 5 MB current-line regression: pending.
- legacy ~15 MB current-line regression: pending.
- v1.9.37/v1.9.37.1 runtime merge: failed on device / retired.
# Current handoff: v2 bounded analyzer

Active branch: `feature/hfamap-v2-bounded-universal-analyzer`.

The active Makefile compiles only Entry/Core/ImageProbe/Resolver. Do not restore the historical generated
source chain into this branch. Run `python3 -m unittest -v tests/test_macho_triage_v2.py`, then test the
new workflow. On device, first open the target menu, press `Scan Menu`, and collect
`HFAMap_Patches.json`, `HFAMap_Analysis.json`, and `HFAMap_Process.jsonl`.

Acceptance requires one legacy-ap and one jailpatch sample to finish without blocking, select the correct
menu dylib, and either export byte-validated patches or explicit unresolved reasons. An empty canonical file
with honest unresolved evidence is preferable to a guessed patch.

CI checkpoint: run `35186351403`, commit `ac74cfaff43fa19ea3f83491c1e955a81946103c`, artifact
`10481758150`; arm64 binary SHA-256
`d6605ec4b3c36bd3daa7d944d9cd24f230dc4905d33ac67ab5659557b6d57413`.

First device archive proved stability but not extraction universality. One `libdragonfevertd.dylib` run selected
the correct payload and completed in about 114 ms, but produced zero canonical features. Do not treat the
58 `missing-offset` entries as features; they were traversal pollution and are filtered in v2.0.1. If the next
run still has no static descriptors, the next evidence boundary is the selected image's exact `loadConfig:` /
Jailpatch runtime-table initialization path, not a broad Objective-C hook.

The v2.0.1 five-device re-test is now complete. Archive SHA-256:
`91fbbfa901d3a75cb35d97dcde58d745a1a75e627532ff4242537f024a661b74`.
Every run inspected the full dyld image set (948–985) and completed in 86.8–137.0 ms. Candidate selection
and traversal filtering are device-confirmed. All runs still exported zero canonical features, so the next
implementation must observe only the selected image's evidenced configuration/runtime-table boundary.
Do not enable the historical process-wide profiler unchanged: its broad class/object traversal violates the
v2 bounded architecture and does not prove the runtime-table layout.
# v2.2.2 当前交接（优先于下文历史记录）

源码为独立包，主仓库 `feature/hfamap-v2-bounded-universal-analyzer` 基点 `85a9b9b`。v2.2.1 点击原菜单闪退，严禁继续实机使用它；六份日志都只到 observer/armed。新版本已删除 setter hook 编译路径，仅开放短时只读扫描。扫描候选从已加载 app-local Mach-O 中选择；主线程快照 UI target；工作队列遍历 target 可达字典/对象，导出 registry、analysis、patch、过程/诊断日志。参考历史成功路径 `HFAMapFamilyRuntimeResolver.m` 中 UI target → owner feature array → label/identifier/type；未移植整套旧运行时模块。只有显式目标镜像、原始字节实时相符才产出 canonical patch。构建和设备状态以 `PROJECT_STATE.json` 为准。
# v2.2.3 当前交接（优先于下文历史记录）

基线 v2.2.2 已被六游戏实机日志确认能完成扫描并导出注册表（1/1/5/14/1/3），但是全部 patch 仍为 0。v2.2.3 新增每条功能数组与目标菜单镜像内描述符对象的**显式关联**，严格区分 `ivarOffset` 与 Patch VM RVA；不调用 setter、不装 hook。身份字段添加 `menuUUID/hostBundleID/hostVersion/hostBuild`，用于核对所选菜单镜像和 App 版本，不能代替目标 UnityFramework 身份。源码单独交付，GitHub 临时构建后恢复到 `feature/hfamap-v2-bounded-universal-analyzer` 的 `85a9b9b` 基点。下一步按 `PROJECT_STATE.json` 收集六份新的实机输出与匹配二进制、验证字段值与真实地址。
# v2.2.5-dev 当前交接（优先级最高）

当前源码是已完成 Linux/Theos arm64 交叉编译的 v2.2.5-dev Evidence Graph。输入基线为 v2.2.3 七组实机日志和 v2.2.4 独立源码包；不要将此前 SHA `425053cd...` 的交付 dylib 当作本开发版产物。

日志矩阵确认 7 款/27 按钮/0 patch；Earn to Die Rogue、Dragon Fever TD、Rise of Berk 的菜单 UUID 与提供二进制完全一致。三份菜单静态证据确认 160-byte 描述符的 `offset` getter 指向对象 `+0x48`、`signature` getter 指向 `+0x58`。当前改动输出跨镜像包装器实现位置、UUID 和 raw ivar，但不调用 getter、不装 hook、不写目标内存。

主机测试 14/14 通过。固定 Theos `dd5c14bb...`、Linux iOS 工具链 `test-210562a` 和 iPhoneOS 16.5 SDK `0222fd54...` 的 arm64 编译、链接、strip 与 ldid 签名通过；二进制 SHA256 以交付目录的构建记录为准。该状态不等于 macOS CI 已运行，也不等于实机验证。下一步做先 Legacy-AP、后 Jailpatch 的分阶段实机采样。

交付约束：每个新版本必须同时交付源码包、同版本 arm64 dylib、SHA256 与构建/验证记录；缺少 dylib 时不得标记为完整交付。

# v2.2.6-dev 当前交接（优先级最高）

当前本地源码已从 v2.2.5-dev 更新为 v2.2.6-dev。输入归档 SHA256 为 `7365478ddc13d6af8b289ed1e7373714d09bc0349dbad991cd60007c9795eb0d`；日志明确来自 `2.2.5-dev-evidence-graph`，7/7 完成、27 按钮、0 patch。

GitHub 高价值基线：`feature/hfamap-v1933-original-byte-resolver` 的状态文件记录 runtime-record 样本曾实机完成 3 features / 8 static patches；`zpatchig/SUCCESS_PATTERNS.md` 要求使用真实 wrapper getter/secret blob、唯一当前镜像解密指纹和 original-byte truth gate。当前实现采用这些通用约束，不采用旧固定 `getter+0xD00`、旧 RVA 或样本类名。

Legacy/AP 路径：同一 feature container 的 descriptor array -> 0xA0 descriptor -> `+0x40` patch wrapper / `+0x48` offset wrapper -> wrapper 唯一 pointer ivar -> bounded secret blob -> unique current-image decrypt fingerprint -> scratch-copy plaintext -> target UUID/RVA/live original validation。类型擦除 `@"?"` 时必须同时满足 descriptor size 和 selector fingerprint。

Jailpatch 路径：记录 `C4M0Manager` class image，以及 `loadConfig:`/`loadPolicies` IMP image/UUID/RVA；不调用方法。Dragon 匹配主程序 UUID `9ABF467E-052E-3A43-9347-EEF0E7D75394` 和菜单 UUID `4C4C44F1-5555-3144-A173-5161C6E74781`，但本地缺 `iGameGod.framework` 二进制，因此实现镜像仍需设备日志确认。

验证：18/18 主机测试通过；两次 Linux/Theos clean arm64 build 逐字节相同；最终 dylib SHA256 `6d1db12b39c304e2e38e9de31255950a6e3d528ebe772e54540a52aa08d9c721`。没有 Git 工作树，未提交、未推送、未运行 GitHub Actions。v2.2.6 尚未实机运行。

下一步顺序：Earn 单次干净扫描 -> Rise 擦除类型扫描 -> Dragon `runtimeEvidence` 归属扫描。收集六类输出并核对 `decodeEvidence/decryptEvidence/canonicalPatch`。若解密候选不是唯一或 original bytes 不一致，必须保持 unresolved。

# v2.2.7-dev 当前交接（优先级最高）

输入 `日志2.zip` SHA256 为 `7c8e1cd0129c98e55cdd890435c283b2ed36b1020abc4469f1dbb6d3da196280`。日志来自 `2.2.6-dev-pointer-evidence`：七个首轮 session 全部完成；Earn 输出 15 条、Archery 1 条、Heavenfall 1 条 byte-validated canonical patch。目标均为运行时枚举到的 `UnityFramework`，记录含 UUID、preferred Mach-O VM offset、patch、original 和 live-byte match。Backpack、Dragon、Rise、Zombie 仍无 canonical patch，保持 unresolved。

用户报告 `Scan Menu (5s budget)` 第二次点击必现闪退。归档没有 `.ips`，且每个 App 只有一个完成 session，因此没有崩溃 PC；源码和实际编译命令共同给出高置信根因：构建未启用 ARC，两个 `dispatch_once` 静态缓存却由 autorelease convenience constructor 创建。首轮 serial worker block 结束后 pool 可释放它们，第二轮成为 use-after-free。v2.2.7 将 signal set 和 decrypt cache 改为 process-lifetime `alloc/init`；解析算法和 canonical gates 未改。

验证：21/21 主机测试通过；Linux/Theos arm64 两次 clean build 完全一致；最终 dylib 108432 bytes，SHA256 `0862dcaa83de639ac9afd4fe88318925e928914315b1af7aaccc226f9f8972de`。CI 未运行，v2.2.7 未实机验证。

实机下一步：打开原菜单，等待每次状态完成后连续按三次 Scan Menu。期望 Diagnostics 出现三个不同 session，各自 `start -> complete`；三次 canonical tuple 必须一致。若仍崩溃，必须补 `.ips` 或系统 crash report，并保留崩溃前 Diagnostics，不能仅凭按钮现象继续猜测。

# v2.2.8-dev 当前交接（优先级最高）

新增独立 `HFAMapPatchV1` 导出层。扫描仍先由 Resolver 产生带 target UUID、offset 语义和 live-original 证据的 canonical feature；导出层不参与识别或解密，只将已经验证的记录聚合为用户要求的 `com.hfa.patch/v1`。输出文件为 `<App名称>_HFAMap_Canonical.hfapatch.json`，现有 `Patches.json`、`Analysis.json`、`FeatureRegistry.json` 保留。

Earn 当前日志的安全输出应为 10 个 feature group / 15 条 patch，ID 是 `0,1,2,3,4,7,8,9,10,11`。`Unlimited Posters` 与 `Max Level` 当前仍 unresolved，所以 ID 5/6 不得从历史样本补入。当前实机 bundle ID 是 `com.notdoppler.earntodierogue`；精确 profile 为 arm64。导出器运行时读取真实值，不采用示例中的 `com.notdoppler.earntodierogue1` 或固定 arm64e。

导出器对 malformed hex、offset、字节长度不一致和同 target+offset 冲突全部拒绝整包。验证为 26/26 主机测试通过，两次 arm64 clean build 相同，dylib SHA256 `e5ab1eaf03bc91bdaa709f080cd1730f07549f97475d54b3730bd2f8a98020cb`。没有 Git 工作树，未提交、未推送、CI 未运行、v2.2.8 未实机验证。
# Fuel/Boost menu-hook evidence (2026-09-21)

The new static evidence supersedes the assumption that Fuel/Boost can only be completed by an exact-build fixed-RVA profile. The menu does not contain plaintext Unity RVAs, but it does contain enough semantic evidence for a generic runtime-guided resolver:

- shared callback: `EarntoDieRogue.dylib+0xB88D8C`;
- hook install function: `+0xB88E44`;
- identifier-to-field mapping: `Fuel -> +0xB8`, `Boost -> +0xBC`;
- replacement value: `0x4B18967F == 9999999.0f`;
- original function slot: `+0xD31520`;
- current identifier/state slot: `+0xD31518`;
- target is dynamically/signature resolved; no Fuel/Boost Unity RVA constant is present in the menu dylib.

Matching UnityFramework UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8` places both field consumption sequences in one function `0x2D9827C–0x2D98FB8`. Bounded ARM64 data flow reaches `+0xBC -> 0x2D9887C` and `+0xB8 -> 0x2D98AC8` without using those RVAs as resolver input.

Next implementation should be a generic `Menu Hook Semantic Resolver`: observe the final HookManager/MSHookFunction target/replacement/original tuple, bind the replacement to the menu identifier, extract object field semantics from the replacement, then analyze only the resolved target function for unique matching load/arithmetic/store flows. Preserve all current canonical truth gates. Do not add an Earn-specific function or copy the two known RVAs into the resolver.

Detailed evidence: `HFAMap_v2.3.2_FuelBoost菜单通用化二进制分析.md`.

# v2.3.4 `日志2(7)` 当前交接（优先级最高）

输入 SHA256 `a582ca70bfcf99794b7067c65ad19c311dd7ec84eb18214024013775ab7624af`，6 款共 19/19 sessions complete。v2.3.4 Block probe 的机械目标已实机通过：22 条记录全部稳定、只读、非 canonical，没有执行/复制/释放 Block，没有安装 Hook 或写内存。

但原语义假设已被否定。Dragon `0x84A8`、Earn `0xB8EB1C`、Path `0x66F8`、Whisper `0xB8EAB0` 的 matching binary 函数体都只是 `_NSLog(@"iGMM Initialized")`。这些 Block 属于 UI target 的公共初始化状态，`same-ui-target-object-graph` 不足以证明其属于当前 label。禁止从这些 RVA 继续推导游戏 patch。

Path 的第二条字典证据有价值：`kButtonTapHandler` 的外层 invoke `0x66B0` 调度 global Block `0x440080`，inner invoke `0x66C4` 取得 image slide 并跳到 preferred RVA `0x3DEC9A0`。当前字典语义是 Debug Menu runtime action；不要按日志中的宽 `labelContext=Damage Multiplier` 绑定。下一实现应解析 nested Block/action target provenance，并先做 import/string classifier 排除日志 wrapper。

本轮成功基线：Earn 14 groups / 20 patches / 0 unresolved；MeChat 4 / 6 + Points unresolved；XP Hero 1 / 1 + Currency/Exp unresolved；Dragon 5 与 Path 4 项 runtime-only；Whisper Energy/Currency unresolved。完整报告见 `HFAMap_v2.3.4-dev_日志2(7)实机验收.md`。

本轮仅做日志和匹配二进制分析、文档更新；没有源码修改、编译、CI 或新的实机运行。现有 v2.3.4 dylib SHA256 仍为 `9938e35952181567d8b4fd3a000c43d8dc5585f4c9993f8043dc573ebc82f6ef`。
