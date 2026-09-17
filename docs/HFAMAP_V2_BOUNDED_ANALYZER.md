# HFAMap v2 Bounded Universal Analyzer

## 结论

旧扫描路径不适合作为通用主线。其卡死风险不是单个循环，而是递归枚举磁盘、映射完整
Mach-O、主线程 UI 深度遍历、对象图扩张和未知 Objective-C getter 调用叠加后没有统一预算。
v2 从零启用四个文件：`HFAMapEntry.mm`、`HFAMapCore.mm`、
`HFAMapImageProbe.mm`、`HFAMapResolver.mm`。旧源文件仍在 Git 历史/工作树中供取证参考，
但 Makefile 不再编译它们。

## 有界发现

1. 只遍历 dyld 已加载镜像，最多 512 个；不递归扫描 app 的 Frameworks 目录。
2. 只考虑主 bundle 内镜像，排除主程序、UnityFramework、HFAMap 本身和注入框架。
3. 只扫描 `__cstring`、`__objc_methname`、`__const`，每个镜像总计最多 32 MiB。
4. UI 框架证据必须与 descriptor/Jailpatch 证据组合；孤立字符串不是候选。
5. 候选最高分低于 50，或前两名分差小于 10，拒绝自动选择并写出原因。

宿主机离线工具 `tools/hfamap_macho_triage.py` 使用同一组规则。用户提供的十个样本全部
只读解析成功，分成 7 个 `legacy-ap` 和 3 个 `jailpatch`。样本哈希与期望结果固定在
`tests/menu_samples_v2_manifest.json`。

## 功能解析与真实性门

解析器只从当前可见菜单的 `UIControl` 出发，并仅接受 class image 属于已选菜单 dylib 的
target。对象图上限为 256 个 target、256 个容器、每容器 128 个元素；不调用菜单类的未知
getter。名称、offset 和 patch 必须存在于同一个 dictionary/descriptor 证据单元。

记录进入 `HFAMap_Patches.json` 前必须同时满足：

- 名称非空；
- offset 可无歧义解析；
- patch 是 1–256 字节的 NSData 或严格十六进制；
- offset + patch 长度唯一落入一个已加载 app-local 可执行段；
- 对应实时字节可读取并写入 `currentBytes`；
- 如果 descriptor 提供 original，则长度必须与 patch 一致后才输出 original。

不满足这些门的按钮只进入 `HFAMap_Analysis.json`，并带有例如 `missing-offset`、
`ambiguous-target-image`、`offset-outside-executable-range` 的拒绝原因。观察到 action 或共享
dispatcher 绝不自动等价于静态 patch。

## 时间与输出

一次手动扫描总预算为 5 秒：镜像发现 2 秒、主线程菜单快照/解析 2 秒、余量用于导出。
重复点击在扫描期间返回 `busy`。每个阶段把开始、完成、超时、计数和拒绝原因写入
`HFAMap_Process.jsonl`；可用补丁写入 `HFAMap_Patches.json`；完整证据和 unresolved 项写入
`HFAMap_Analysis.json`。

## “通用”的边界

通用表示无需针对游戏名、dylib 文件名、固定 class 名或固定 offset 写 profile；不表示可以
从任意经过加密、运行时生成或服务端下发的逻辑中静态猜出 patch。若 descriptor 只在点击后
解密、patch 由 native dispatcher 动态生成，v2 会安全地报告 unresolved。后续适配必须在确切
注册/解密边界增加受限观察器，并保留同样的 provenance 和字节真实性门，不能退回广域 hook。

## 验证状态

- Python 语法和合成 Mach-O 单元测试：通过。
- 用户提供的 10 个真实菜单 dylib 离线分类回归：通过。
- arm64 Theos CI：等待新分支首次运行。
- 真机 injection、菜单解析和导出：等待验证。
