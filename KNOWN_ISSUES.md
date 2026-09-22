# Known Issues

## v2.3.9 IL2CPP Runtime Resolver 边界

状态：源码已提交、69/69 tests 与 Actions Run `35722643492` 编译通过；实机待验证。

- “运行时抓方法”不是全 IL2CPP 构建必然可用：需要 domain/assembly/image/class/method enumeration exports，或后续 metadata-assisted internal resolver。导出被隐藏时本版会明确返回 `required-il2cpp-enumeration-exports-unavailable`。
- 候选由菜单文字提示和通用动作词排序，只是缩小范围。方法命名完全混淆、业务入口无语义词、调用进入共享 generic thunk 时可能漏报或多义。
- 最多安装 96 个 direct instruments；高于上限的候选会截断。不得把“未进入前 96”解释为方法不存在。
- `DobbyInstrument` 会临时改写方法入口代码，但不替换原函数、不主动调用 managed method；停止必须恢复成功。restore failure 非零时停止继续测试并保留日志。
- ARM64 寄存器 token 是调用现场证据，不代表已理解参数类型。未结合 matching binary/metadata/ABI 前禁止解释对象、字符串、float、struct 或返回值。
- arm64e/PAC、共享/泛型 thunk、极短函数或受保护代码页可能导致 instrument 安装失败；结果必须按每个候选安装状态判断。
- Fuel/Boost 已验证的 static Patch 证据保留。runtime observation 是新增证据通道，不覆盖旧路径。

## v2.3.8 IL2CPP Runtime Probe 首版边界

状态：Actions Run `35697312404` 已编译通过；尚未实机。

- 目标进程若未提供可逆 `DobbyHook/DobbyDestroy`，探针会返回 `reversible-hook-backend-unavailable`，不会降级为无法可靠恢复的 Hook。
- IL2CPP exports 可能被 strip/隐藏；任一必要 export 缺失时返回 `required-il2cpp-exports-unavailable`。
- 游戏可能在 Arm 前已缓存 `Il2CppClass/MethodInfo`，因此抓不到 class/method resolver；也可能直接调用 method pointer 而绕过 `il2cpp_runtime_invoke`。0 event 不是“不存在 runtime method”的证据。
- UI sidecar 与原 action 的执行先后不保证；1.5 秒关联是候选证据，不等于因果证明。
- pointer token 只用于同一 session 内关联，不是 RVA、不是跨启动稳定身份，也不能直接生成 patch。
- 当前未读取 MethodInfo 内部布局、未验证返回/参数类型、static/instance、hidden MethodInfo 参数或线程要求，因此禁止主动调用。
- 停止时需检查 `hookRestoreFailureCount=0` 与 `hooksRestored=true`；否则本轮设备结果作废并停止重复测试。
- Earn Fuel/Boost 是 callback field `+0xB8/+0xBC` 到 `Car.FixedUpdate()` 的字段数据流，不能因本探针加入而改写为 runtime-method-call。

## v2.3.7 `日志2(10)` 状态与 action sink 实机结果

状态：Probe 生命周期和 exact action entry 已实机通过；custom state 与 action sink 语义未通过。

- 12/12 sessions 完成、12/12 target list restored、0 restore failure、无重复 Arm 闪退；这关闭了“探针是否能稳定运行”的问题。
- 40/40 exact action records 为 `unresolved-action-sink`。96-byte classifier 未跟随共享 ObjC handler 内的 selector dispatch/内部调用；unresolved 不代表没有业务逻辑。
- 六款 custom control 均输出 `primitiveIvars=[]`、无 `stateChangesAfterEvent`。
- Dragon/Earn/Path/Whisper matching binary 已证明类中存在 `isOn` BOOL backing ivar +56 与 `currentState` Q backing ivar +80；名称被混淆，当前名称过滤在读取前漏掉它们。这是四款已证实根因。
- MeChat/XP 没有 matching menu binary，目前只能推断相同共同祖系布局。
- sidecar callback 的执行顺序不承诺在原 action 前或后，因此 `stateImmediate` 只作观测；`stateSettled` 使用下一主线程周期，才是优先状态证据。
- action IMP/RVA 不是 patch RVA。未闭环 target function、instruction semantics、live original bytes 前不得进入 Canonical。
- Whisper Energy/Currency、MeChat Points、XP Currency/Exp 均未获得新 offset/patch。
- 下一版应由 ObjC property metadata 的 `T`/`V` 找 backing scalar ivar，而非扩大混淆名称词表。

## Legend title secret VA 尚缺匹配二进制独立复算

状态：实机语义结构已交叉验证；静态地址复算待输入。

两轮 Legend 2.0.3 实机输出已稳定证明 12 个 `identifier + plaintext title + descriptorEvidence[]` records、16 个 descriptor/patch，且内部 title UTF-8 byte length 与现有静态 VA 表逐项一致。但当前工作区没有菜单 UUID `F4A420C5-E116-3AE9-8943-C2D9E74F4CEC` 的 `LegendofSurvivors.dylib`，所以 `0xBBDD58..0xBBE688` 不能标记为本轮独立反汇编确认。

取得匹配 dylib 后必须复核 Mach-O UUID、preferred VM address、secret object header、decrypt fingerprint、注册调用参数与 descriptor array membership。地址复算不影响已经由实机 registry 证明的组级名字绑定；双 descriptor group 内逐项顺序仍应保持 unresolved，直到注册参数或目标函数语义能区分两个子项。

## v2.3.6 自定义开关状态不可见

状态：事件与 action 绑定实机通过；ON/OFF state 未验证。

`日志2(9)` 中六款开关控件都正确产生 `value-changed`，并绑定到各自 menu-local action IMP。但这些混淆类不是 UISwitch：`switchOn` 不存在，继承的 `selected` 在所有 callback 中始终 false。因此 Probe 目前不能证明每次事件后的真实开关值，也不能以 callback 奇偶数替代状态证据。

v2.3.7 已实现只读 menu-local primitive ivar inventory 和 Arm/immediate/settled diff，但尚未实机证明能命中这些混淆控件的真实状态字段。不得把“已实现”写成“ON/OFF 已验证”。

## v2.3.6 Path dyld fallback 实机未命中

状态：outer dispatch chain 通过；nested target unresolved。

v2.3.6 增加的 `dladdr`-missing-name → `dlsym` address equality fallback 在 `日志2(9)` 中没有识别 inner `+0x66C4` 的 dyld slide call。结果仍为 imports `[objc_msgSend]`、`unresolved-block-semantics`，没有 `0x3DEC9A0`。

下一版应输出 direct BL target、stub words、ADRP page、GOT slot、resolved pointer、dladdr image/name、两个 dlsym candidate address，并显式处理 arm64/arm64e pointer normalization。所有输出仍须有界、只读；在 target 未唯一解析前保持 analysis-only。

## v2.3.6 Interaction Probe 实机结果

状态：多游戏 Probe 核心机制通过；上述两项未完成。

- Slider coalescing 已用 39/47 sample 两轮实机验证；没有触发 32 logical-event limit。
- 真实 restore 反查已在 12/12 sessions 得到 failure count 0。
- Path dlsym fallback 已实机确认仍不够，必须补充地址级诊断。
- 自定义 control 同时注册 TouchUpInside/ValueChanged 时，sidecar callback 参数仍不含触发 mask；v2 只能标记已注册事件集合与 `ambiguous-control-activation`，不得伪造精确事件类型。
- `RuntimeProbe.json` 仍表示最后一轮；跨轮完整轨迹以 Diagnostics 为准。

## v2.3.5 Runtime Probe 实机结果

状态：多游戏 Probe 机制通过；Path nested target 部分失败。

- v2.3.4 已实机证明 Block header/invoke 稳定，但公共 owner Block 在四份 matching binary 中只是 `NSLog(@"iGMM Initialized")`。v2.3.5 classifier 尚需设备确认能正确解析 live stub/GOT 与 CFString。
- UIControl sidecar target 理论上不替换原 action，但仍会临时改变 target list；必须验证停止后 `targetListRestored=true`，且原菜单行为不受影响。
- 自定义 UIGestureRecognizer、非 UIControl、直接 C++/Swift action 不会被首版 Probe 捕获；`no-eligible-controls` 或 0 event 是诚实结果，不得扩大为全局 `objc_msgSend` hook。
- TouchUpInside 与 ValueChanged 可能让同一次交互产生两条事件；需用 control token、time 和 action 集合判断，不按事件数机械当按钮数。
- Probe 只建立用户点击到 ObjC target/action/IMP 的绑定，不能单独生成 patch。runtime action target 仍须闭环到 target UUID、executable range、original/enabled 和 live bytes。
- `日志2(8)` 的 6 款均完成两轮 Arm/stop，未出现第二轮闪退或重复 sidecar callback；12/12 输出 restored。
- Dragon 真实 slider 产生连续 ValueChanged 与重复终值，证明旧摘要和 event budget 不适合直接按 callback 计数。
- Path 外层 dispatch chain 通过，但 nested target 未恢复为 `0x3DEC9A0`；不能把 v2.3.5 Block semantic 验收写成全通过。

## v2.3.3 已验证正常覆盖路径，故障拒绝路径仍待实机

状态：部分实机通过。

`日志2(6).zip` 中 Earn 两轮都满足完整覆盖门并稳定输出 Fuel/Boost；因此正常 success path 已实机验证。尚未验证的是闸门真正遇到异常时能否按设计 fail closed：

- `vm_read_overwrite` 失败或短读；
- 192 MiB 单段或 384 MiB 全局 cap 截断；
- 5 秒 deadline；
- 单字段超过 32 candidates。

这些边界已有主机源码合同/模型测试，但没有设备故障注入证据。下一步要求每种受控异常都产生 `target-scan-incomplete`、`scanCoverage.complete=false`，且 hook-semantic canonical 为 0。禁止用正常路径两轮成功替代失败路径验证。

### Earn 重复轮数未达到计划值

当前 v2.3.3 只有两轮 Earn，同轮与 v2.3.2 四轮完全一致，但 ROADMAP 的本版门槛是至少五轮。还需补三轮；功能启停与 original 恢复也仍未验证。

## v2.3.3 Semantic Coverage Gate 尚未实机验证

状态：主机测试与双 clean build 通过；设备运行待验证。

v2.3.2 能在当前样本输出正确 Fuel/Boost，但旧实现没有证明“所有 eligible executable bytes 都已经扫描”。若 `vm_read_overwrite` 局部失败、384 MiB 全局预算或 192 MiB 单段预算截断、5 秒 deadline 到期、或单字段候选超过 32，已扫描子集中的唯一候选不能代表全目标唯一。

v2.3.3 已改为 fail closed，并导出 `scanCoverage`。剩余风险：

- 大型游戏可能因现有 byte cap 被正确拒绝，需要根据真实覆盖数据优化分段策略，不能直接放宽后宣称成功；
- 读失败原因目前只计数，不记录具体 VM range/kern code；若实机出现失败，下一版应添加有界失败摘要；
- 新 gate 可能让曾经“碰巧在已扫描范围内找到唯一候选”的游戏从 resolved 变为 incomplete，这是预期安全行为，不应回退；
- v2.3.3 尚无 Earn 实机日志，不能声明 Fuel/Boost 在本版仍输出 14 groups / 20 patches。

下一步：Earn 五轮正常扫描 + timeout/read/cap 故障注入；正常路径必须完整覆盖，故障路径必须 0 hook-semantic canonical。

## v2.3.2 Fuel/Boost 扫描已通过，功能启停仍待验证

状态：解析/导出实机通过；功能效果未验证。

`日志2(5).zip` 中 Earn 四次连续扫描均自动输出 Fuel/Boost，最终 14 groups / 20 patches、0 unresolved、0 rejected，offset/original/enabled 四轮一致。二次扫描闪退未复现。

日志没有记录：

- 启用 Fuel 后燃料是否停止减少；
- 启用 Boost 后加速条是否停止减少；
- 关闭开关后 original bytes 是否恢复；
- 两项分别启停以及同时启用的交互。

因此当前不能将 Fuel/Boost 的实际游戏效果标为 device verified。下一步必须在值耗尽前分别启用、观察消耗、关闭并验证恢复；发生异常时保存 patch consumer 日志和目标内存字节。

### Fuel 离线 raw candidate 数与实机不同

状态：不影响本轮唯一解析，但保留为证据差异。

离线对提供的 UnityFramework 文件做宽范围等价扫描时，Fuel `+0xB8` 曾观察到 2 个 raw flow；`日志2(5)` 四轮实机 resolver 均记录 `rawTargetCandidateCount=1`。最终目标 RVA、UUID 和 original bytes 与历史静态分析一致，Boost 也共同指向同一目标函数，因此本轮结果可信。

可能差异层包括离线脚本与产品扫描边界、磁盘文件与运行时映射字节，但当前日志不足以确定具体原因。不得删除 same-callback consensus 门；若后续需要解释该差异，应对同一实机版本保存目标内存页或加入只读 rejected-candidate 摘要，而不是根据已知 RVA调整筛选。

## Verified Profile 不是纯菜单自动发现

状态：历史 profile 路径仍依赖 exact-build 离线分析；v2.3.2 的 menu-hook-field-dataflow 通用候选链已通过 Earn 四轮实机扫描和导出。跨第二种菜单实现的通用性、实际补丁启停效果仍未验证。

Earn 的 14 个按钮共享同一个菜单 action，菜单结构只提供 12 个完整 patch definition。新静态证据表明 Fuel/Boost 走另一条菜单 Hook 路径：菜单 callback 暴露 `Fuel -> +0xB8`、`Boost -> +0xBC`，再由目标函数字段数据流定位代码 patch。因此：

- 可以通用化 profile 匹配、身份门、live-byte 门和 canonical 合并；
- 不能把按钮名称到 RVA 的启发式关联直接标为 byte-validated；必须取得 Hook target、field offset、唯一 load/arithmetic/store 候选和 live bytes；
- 不能跨 UUID/版本复用历史 RVA；
- 不能只按 `Unlimited Fuel` 等通用标题匹配，必须以当前菜单 registry identifier + exact app/image identity 联合匹配；
- 历史 profile 写的是目标镜像 architecture `arm64`，而当前 package architecture 为 `arm64e`；实现时必须区分 host package architecture 与 target image architecture，不能混作同一 gate。

IL2CPP 自动候选生成若开发，应作为离线 suggestion/profile builder；只有经过 matching binary+metadata、方法/字段映射、ARM64 数据流、原始字节和目标 UUID 验证后才能进入运行时 profile。

## v2.3.1 Earn 部署版本不一致

状态：已解决。后续 `新建文件夹.zip` 已确认 Earn 加载 v2.3.1，并完成五次连续扫描。

历史原因：`日志2(4).zip` 中其余 12 款诊断版本均为 `2.3.1-dev-shared-offset-export`，只有 Earn 为 `2.3.0-dev-jailpatch-target-resolution`。清除旧注入并重新部署后，Earn 五轮 v2.3.1 已全部通过。

本轮每款只有一个 session，不能作为“第二次 Scan Menu 不闪退”的新增回归证据；该问题继续沿用 v2.2.9/v2.3.0 多轮日志的历史通过状态。

更新：Earn 新归档含五个同进程 session，5/5 complete，已为 v2.3.1 提供二次至第五次扫描不闪退的新证据。

## v2.3.1-dev 实机验收后剩余问题

### Earn Posters/Prestige 共享 patch site

状态：已实机通过。Earn v2.3.1 五轮均输出 12 groups / 18 patches / 1 shared site / 0 rejected。

- `Unlimited Posters`：`UnityFramework+0x2E25904`，4 bytes，`D03180D2 -> 08E0BF12`。
- `Prestige Pass Unlocked`：同起点，8 bytes，`D03180D2CBEDD914 -> 20008052C0035FD6`。
- 用户确认原菜单允许多个按钮使用同一 offset。两条 original 的重叠 4-byte 前缀一致，因此不是证据矛盾；它们是共享 patch site、不同 enabled 语义。
- v2.3.1 已保留两个 feature，并把运行时启停相互影响写入 sidecar；禁止跨 feature 静默去重。
- 只有共享范围内的 original bytes 互相矛盾时，才应拒绝相关记录。

### Patch v1 拒绝后可能残留旧文件

状态：v2.3.1 源码已修复并通过编译，尚待实机故障注入验证。

v2.3.0 的 rejected 分支不会删除旧文件。v2.3.1 已让 Canonical 与 sidecar 使用原子写入，并在 package 构建、序列化/写入失败时删除相应旧输出。仍需在实机 Documents 中预置旧文件后触发失败路径验证。

### Fuel/Boost 新通用路径尚待实机

Earn 的 `Unlimited Fuel`、`Unlimited Boost` 在 v2.3.1 仍为 `missing-offset`。v2.3.2 已编码并编译通用候选链 `menu exact identifier -> callback field +0xB8/+0xBC -> executable field dataflow -> fsub patch`。离线全段扫描发现 Fuel 原始有两个候选，因此必须保留同 callback 多字段共识门；仅按单字段会产生歧义。当前尚无 v2.3.2 实机日志，不能声称已自动导出 14 groups / 20 patches；旧版本专用 RVA仍不能作为 resolver 输入。

### 部署文件名仍为 v2.2.9

实机加载路径名是 `HFAMapUniversal-v2.2.9-dev.dylib`，但 Mach-O UUID 与 v2.3.0 交付完全一致，诊断版本也为 v2.3.0。功能上不是旧二进制；后续部署应同步文件名以避免验收歧义。

## v2.3.0-dev 交付时边界（后续实机状态已更新）

- 交付时 v2.3.0 仅完成 35/35 测试和双 clean build；后续 `日志2(3).zip` 已确认 Rise 实际读取 original 并稳定生成 3 features / 8 patches。当前问题以上方实机后条目为准。
- `unique-offset-executable-range` 是 fail-closed 归属，不是按应用名猜测。如果多个 executable segment/image 同时包含地址，本版会保持 unresolved。
- Rise 的 8 个地址在 v2.2.9 日志快照中唯一落入主程序范围；游戏或主程序更新后必须重新依赖当前 dyld image UUID/range 和 live bytes，禁止复用旧地址。
- 若扫描前原菜单已启用 patch，live bytes 可能已经等于 enabled bytes；本版会拒绝生成 canonical，需恢复原始状态后重扫。
- 现有 `com.hfa.patch/v1` 不携带 target UUID，实机验收必须同时保存 `Analysis.json`/`Patches.json` 的完整身份与证据。
- Dragon/Path 仍是 runtime-only。v2.3.0 不应凭 identifier、按钮 handler 或 `C4M0Manager` ivar 生成静态 patch。
- 当前源码包不是 Git worktree；未提交、未推送、CI 未运行。

## v2.2.9-dev 当前问题（最高优先级）

- v2.2.9 已由 `日志2(2).zip` 实机运行 37 次，全部完成；第二次扫描闪退未复现。该问题转为“已通过本轮回归，仍保留无 `.ips` 的历史根因限制”。
- `RuntimeActions.json` 是 analysis-only 语义输出，不是可执行 patch 包；`runtimeValue/runtimeToggle/runtimeAction` 不含可移植实现时不得自动执行。
- Dragon 已实机得到 23-method inventory 和 18 个候选，并精确定位 `loadConfig:`/`loadPolicies`；Path/Rise 的 `C4M0Manager` 方法 inventory 为空，只确认 `policies` ivar，不能据此调用或命名隐藏方法。
- Jailpatch UI feature dictionary 与 patch/config table 分离；v2.2.9 不会仅凭按钮 identifier 或 handler 地址生成 offset/patch。
- v2.2.1 的点击 setter Hook 曾导致实机闪退；当前没有 `.ips` 崩溃 PC。v2.2.9 保持零 Hook，未来 observer 必须基于精确方法/对象证据单独设计。
- Rise 已解密 8 组 offset/enabled bytes，但 descriptor 不含 target image 字符串；当前 resolver 因此把 `targetImage` 留为 unresolved。下一版只能在 offset 唯一落入一个当前 executable preferred-VM range 时映射，并必须读取 live original bytes；现有日志不足以手工生成 canonical 包。
- 连续扫描回归已覆盖 8 款、每款 4–5 次、共 37 次。历史崩溃没有 `.ips`，所以“具体崩溃 PC”仍未知，但产品级复现条件已通过本轮验证。
- `com.hfa.patch/v1` 不携带 target UUID；必须同时保存 v2 `Patches.json/Analysis.json`。
- Posters、Max Level、Backpack、Zombie 仍缺当前构建 canonical 证据；禁止填入历史 offset。
- 本地源码不是 Git worktree；当前没有 branch/HEAD/commit，远程仓库需要认证。CI 未运行。

## v2.2.8-dev 已解决状态修正

- Patch v1 “尚未实机生成”已由 `日志2(1).zip` 推翻：八款均生成合法兼容包，3 款非空，共 17 patches。
- v2.2.8 的单次扫描为 8/8 完成，但连续第二次/第三次扫描仍未验证。

## v2.2.0 device validation pending

The arm64 build passed GitHub Actions Run `35431604227`; startup, observer forwarding, timeout restoration and JSON capture have not been tested on an iOS device. On a matching test app: scan, arm, toggle original controls, stop, then inspect `HFAMap_DescriptorCapture.json` and `HFAMap_Diagnostics.jsonl`. Any `restoreConflicts > 0` or missing original menu behavior blocks promotion.

No target App Info.plist was available at build time. The build filename uses the analyzer executable fallback `HFAMapUniversal`. Rebuild with the real target Info.plist to use its `CFBundleDisplayName`, or its `CFBundleExecutable` when the display name is absent.

The initial GitHub artifact included historical `hfamap/dist/*.dylib` files because the upload path was broad. Only the exact v2.2.0 binary is included in the independently verified delivery bundle.

## v1.9.37.10 Earn to Die Rogue profile

### Device runtime validation pending

Status: open.

Fuel/Boost are statically proven and generation-tested, but the new analyzer
binary has not yet been built by GitHub Actions or exercised on device. Required
checks are clean scan output, `14` canonical features, `20` patches, independent
Fuel/Boost enable/disable and original-byte restoration.

### Already-depleted values are not refilled

Status: intentional behavior.

The two patches NOP the subtraction instructions. They prevent additional
consumption but do not assign a full tank. Enable them before Fuel/Boost reaches
zero or start a new driving session.

### Exact-build profile only

Status: permanent safety gate.

The RVAs are valid only for `com.notdoppler.earntodierogue` `1.28.251 (1)`,
arm64, UnityFramework UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, with exact
original bytes. A game update requires fresh metadata and binary analysis.

### Posters/Prestige patch overlap

Status: open / pre-existing.

Both features touch `UnityFramework+0x2E25904`. Posters writes `08E0BF12`
(4 bytes), while Prestige writes `20008052C0035FD6` (8 bytes). Toggle order can
overwrite the shared first instruction. Fuel/Boost do not introduce this
conflict, but the package needs explicit conflict handling or a new independent
Prestige/Posters patch site.

### Generic observed-action classification remains too broad

Status: mitigated for the verified target only.

The generic v1.9.37.9/v1.9.37.10 logic can classify an observed action as
`runtimeAction` even when the action is only a shared menu dispatcher. The exact
Earn to Die profile corrects the two proven records; a future generic fix should
use `dispatcher-observed/unresolved` until independent write/hook/static-byte
evidence exists.

## Current parser-only line: v1.9.36.4 JSONExport

### v1.9.36.4 WayOfKings/iGMM validation

Status: **passed / closed**.

Device archive `归档 6(1).zip` confirmed stable injection, Full Scan completion, 4-feature iGMM diagnostic export and normalized analysis export. It also confirmed:

- `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains preserved;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- `targetIdentities` resolves both `libpathofkings.dylib` and `UnityFramework` with the expected UUID/arm64/cryptid evidence;
- `JSON-EXPORT status=pass features=4 sources=1 targetIdentities=2`.

### Cross-family regression is still pending

Status: open / primary validation gate.

The current v1.9.36.4 parser has now passed the WayOfKings/iGMM family, but the same binary still must be regression-tested on:

- runtime-record/static 5 MB family;
- legacy ~15 MB family.

Do not claim universal/cross-family coverage until both current-line regressions pass.

### Target identities are analysis evidence, not execution authorization

Status: permanent rule.

Read-only UUID/architecture/filetype/preferred-`__TEXT`/cryptid records are for build matching and analysis quality only. They do not authorize hook installation or package execution.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device-confirmed.

WayOfKings uses runtime numeric/native-hook/block behavior. These records remain diagnostic and analysis-only and are not fabricated into `target/offset/original/enabled` static patches.

### v1.9.37 and v1.9.37.1 are retired from the parser mainline

Status: confirmed device startup failure / architecture reverted.

Those builds merged the independent playback/runtime consumer and Dobby into HFAMapUniversal. Both crashed immediately when injected. HFAMapUniversal remains a parser/exporter only.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing a new menu family, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs. A stale canonical package must never be mistaken for current output.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Runtime-record/static 5 MB regression

Status: open / next test.

The current v1.9.36.4 build must reproduce a trusted `com.hfa.patch/v1` package for the static 5 MB family. Required checks include real target identity, preferred VM offsets, original-byte truth and no stale-output contamination.

### Legacy ~15 MB regression

Status: open / follows the 5 MB static test.

The legacy AP/IGSecret family was previously runtime-confirmed on older parser versions. The current v1.9.36.4 binary must still prove that path has not regressed.

## Current CI delivery

Authoritative candidate:

- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
- run: `34907671999`
- artifact: `10372928333`
- binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`
- WayOfKings/iGMM device validation: passed
- cross-family regression: pending
# v2 open issues

### v2.1.0 image ceiling regression

Status: fixed in v2.1.1-dev; device re-test pending.

The eight-run archive contained 947–987 loaded images. v2.1.0 inspected only the first 512, causing five
false `no-loaded-menu-image` results. The ceiling is restored to 2048 while retaining the wall-clock deadline.

### Jailpatch runtime table is not yet decoded

Status: confirmed by both device archives; v2.0.1 re-test reproduced on five targets.

`libdragonfevertd.dylib` was selected correctly and the scan completed, but UI-target object traversal exposed
no offset/patch descriptor. Static strings and Mach-O structure identify a Jailpatch `loadConfig:` and runtime
metadata path, but strings alone do not prove its structure. A bounded observer at that exact boundary is the
next task. The v2.0.1 matrix inspected all 948–985 loaded images and selected the intended payloads, but
all five targets remained at `validated=0`; broader UI traversal is therefore ruled out as the solution.

### Discovery event can mislabel the pre-policy candidate

Status: fixed in v2.1.0-dev; device confirmation pending.

`HFAMapImageProbe` now writes `topCandidate`; the selection stage emits the actual policy-selected image.

### First device build had discovery/traversal defects

Status: fixed and device-confirmed in v2.0.1.

The 512-image cap omitted late-loaded menu images in three runs. A wrapper/payload pair was rejected because
their total scores differed by only eight points. UIKit/Foundation objects polluted unresolved output. The
corrective build raises the bounded cap, applies descriptor-strength tie-breaking and filters non-descriptor
containers.

### Device validation is pending

The host-side parser passes all ten supplied dylib samples and arm64 CI compile/link passed, but the new
Objective-C++ runtime path has not yet been injected on a device. Clean-device regressions are required
before release.

### Runtime-generated descriptors are intentionally unresolved

If a menu decrypts or constructs its patch only at interaction time, a read-only menu snapshot cannot prove
the bytes. v2 reports this instead of converting UI actions into static patches. A future observer must target
an evidenced registration/decryption boundary and remain bounded to the selected image.

### Candidate ties require a future manual picker

When the top two loaded app-local candidates differ by fewer than ten points, v2 refuses automatic selection.
The JSON contains both candidates; a UI picker is not yet implemented.
# v2.2.2 已知边界（当前）

- v2.2.1 六份扫描已选中菜单，但每份在 hook/armed 后点击即闪退；无 `.ips`，真实崩溃指令未证实。v2.2.2 移除该 hook 路径，实机稳定性待验证。
- 菜单注册表可能只包含部分按钮：取决于扫描时 UI target、数组和描述符是否已经初始化；不要把 registry 条数当作已验证 patch 条数。
- 历史 Earn to Die Rogue 特定 UnityFramework 的 Fuel/Boost RVA、原始字节仅适用文档中的精确构建；不能用于本轮六个目标或更新版本。
- 旧扫描档案没有当前可确认的 offset/original/patch 配对；当前可以有名字、0 个 canonical patch，这是符合真值门的输出。
# v2.2.3 当前边界

- v2.2.2 六组扫描各自写完结果，未提供 `.ips`，只能证明扫描产出完成；不等于全面实机稳定性回归。
- 14/14 功能名称在 Earn to Die Rogue 注册表出现，但六款全部缺 offset，canonical patch 均为 0。v2.2.3 只读字段证据尚未实机验证。
- `descriptorEvidence.fields[].ivarOffset` 是 Objective-C 对象内偏移，禁止当做 Mach-O Patch RVA；不能将一组功能名字与共享 target 或邻近描述符强制配对。
- 旧版本 Fuel/Boost 的静态补丁必须经过同一 UnityFramework UUID、原始字节、游戏版本校验才可用于其精确版本。
# v2.2.5-dev 当前问题（优先级最高）

- v2.2.5-dev 已在 Linux/Theos 下完成 arm64 交叉编译和静态二进制验收，但 macOS GitHub Actions 尚未运行。
- 跨镜像 wrapper evidence 尚未实机验证，不能确认 `IGSecretInt/IGSecretData` 的实际实现镜像和 raw ivar 布局。
- Jailpatch 的 UI 功能字典与运行时 patch table 分离；现有日志不足以输出 offset/patch。
- Archery Clash、Backpack Brawl、Heavenfall Arena、Zombie Catchers 缺同版本菜单和目标二进制，不能进行 original-byte truth 验证。
- 任何 wrapper ivar、method IMP、UI action 地址都不得作为游戏 patch RVA。

# v2.2.6-dev 当前问题（优先级最高）

- 新的 scratch-copy 解密和 canonical 生成路径只完成源码、主机测试与 arm64 编译，尚未实机运行；不能声明 v2.2.6 已成功导出 offset/patch。
- 解密指纹是历史实机成功并在三份当前精确二进制中唯一命中的强证据，但仍可能遇到新版本零命中/多命中；实现会 fail closed。
- live original bytes 是扫描当下字节；若目标 patch 已启用则 canonical 记录会拒绝，需恢复原始状态后重新扫描。
- Dragon 当前 UI feature dictionary 不直接持有 descriptor。跨镜像 owner 证据能定位 `loadConfig:`，但在拿到实现镜像/配置对象之前仍不会生成 patch。
- 本地没有 Dragon 同次运行的 `iGameGod.framework` 文件，不能做其离线方法体/运行表结构验证。
- Archery、Backpack、Heavenfall、Zombie 缺同 UUID 目标二进制；即使 secret 解密成功，缺少目标镜像或 live executable range 时仍保持 unresolved。

# v2.2.7-dev 当前问题（优先级最高）

- 第二次扫描崩溃已做高置信源码修复，但输入归档没有 `.ips`/崩溃 PC，v2.2.7 尚未实机连续点击验证；状态不能写成 device-fixed。
- 日志文件每个只包含一个完整 v2.2.6 session，不能直接证明第二轮进入了哪条指令；MRC 静态 autorelease use-after-free 是由生命周期与实际无 ARC 编译命令推断出的根因。
- v2.2.6 的 17 条 canonical patch 已通过运行时 UUID/范围/live-original 门，但仍只适用于日志中的精确目标 UUID；禁止跨版本复用 RVA。
- Backpack Brawl、Dragon Fever TD、Rise of Berk、Zombie Catchers 仍为 0 canonical patch；不得因三款成功而降低其 fail-closed 条件。
- Jailpatch 仍需运行时表所有权/结构证据；本次 rescan 修复不解决该家族 offset/patch 解析。

# v2.2.8-dev 历史边界（后续日志已修正验证状态）

- v1 compatibility exporter 在发布当时仅完成编译；后续 `日志2(1).zip` 已确认八款均实机生成文件，当前状态为 runtime-verified。
- `com.hfa.patch/v1` 兼容格式本身不携带 target UUID；完整身份与证据仍以并行的 v2 `Patches.json/Analysis.json` 为准。
- Earn 示例中的 `Unlimited Posters`、`Max Level` 当前日志仍 unresolved；示例值不得伪装为本轮 byte-validated 输出。
- 用户示例 bundle ID `com.notdoppler.earntodierogue1` 与当前日志/NSBundle 证据 `com.notdoppler.earntodierogue` 不同；导出器始终使用运行时真实值。
- 若同一 target+offset 被不同功能赋予不同字节，导出器拒绝整包；不会按输入顺序静默覆盖。
# Fuel/Boost runtime-hook conversion is not implemented

- Symptom: current scanner recognizes `Fuel` and `Boost` but exports `missing-offset`.
- Root cause: these controls use a shared runtime Hook callback that writes object fields `+0xB8/+0xBC`; they do not carry plaintext UnityFramework patch descriptors or fixed RVAs.
- New evidence: the menu callback, hook install path, field offsets and write value have been statically recovered; matching Unity code contains unique field consumption sites that reproduce the verified patch RVAs.
- Remaining engineering gap: capture the dynamically resolved hook target, associate it with the current menu control, and implement bounded ARM64 field-flow-to-patch synthesis.
- Safety requirement: zero/multiple candidates, non-executable targets, live-byte mismatch or target ambiguity must remain unresolved. Never silently reuse historical offsets across versions.
- Validation state: static and binary cross-validation complete for Earn 1.28.251; generic implementation and device validation pending.

# v2.3.4 common Block semantic false association

Status: probe mechanics device-verified; semantic classification requires a follow-up implementation.

- Symptom: `blockProvenanceEvidence.labelContext` appears to associate an owner `ivar +0x98` Block with the first feature label in each menu.
- Root cause: the association is only `same-ui-target-object-graph`; it propagates a nearby label onto a root/common UI Block without proving descriptor membership.
- Binary proof: matching Dragon, Earn, Path and Whisper menu binaries show the recovered invokes only call `_NSLog(@"iGMM Initialized")` and return.
- Risk: treating this Block as a business handler would direct static analysis into an initialization logger and could create false name/handler bindings.
- Existing mitigation: every record is `analysisOnly=true`, `canonicalEligible=false`; v2.3.4 never invokes/copies/releases the Block and never installs a hook or writes memory.
- Required fix: resolve first-level import/branch and referenced constants; classify trivial logging wrappers as `nonsemantic-logging-block`; prefer direct feature dictionary fields over common owner ivars.
- Regression rule: instruction-prefix similarity alone is insufficient. MeChat and XP remain unverified until their matching menu binaries are available.

# Path of Kings action Block not yet convertible to a patch

Status: static action chain recovered; patch semantics unresolved.

- `kButtonTapHandler` outer invoke `0x66B0` dispatches inner invoke `0x66C4` on the main queue.
- Inner invoke computes an image slide and branches to preferred RVA `0x3DEC9A0`.
- The containing dictionary represents Debug Menu, not Damage/Defence/God Mode; the current broad label context must not override dictionary identity.
- This is a runtime action target, not proof of `original/enabled` bytes. It must remain out of `com.hfa.patch/v1` until a target-byte transformation and all truth gates are demonstrated.
