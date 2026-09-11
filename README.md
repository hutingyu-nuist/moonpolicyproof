# MoonPolicyProof

**在发布网络访问规则之前，回答“哪些五元组从拒绝变成放行、哪些从放行变成拒绝”，并给出可独立回放的具体包。**

这是基于现有 MoonBit 生态库的实质扩展：复用 `BeiLaDuo/cidr-audit@0.1.2` 的 IPv4/CIDR 模型、`oyjh0381/moonbdd@0.1.0` 的 ROBDD 引擎；本项目实现五元组语义编译、有序规则剩余域、双向差异、反例回放、业务断言和调用工具。不是新的 CIDR/BDD 基础库，也不声称全球首次实现 ACL 语义分析。

## 适用人群与交付边界

- 平台工程师：部署前审查访问范围放宽或收紧，输出机器可读反例。
- 规则维护者：找出被多条前序规则联合遮蔽的死规则，以及仍部分生效的规则。
- 应用团队：把 HTTPS 可达、SSH 隔离等约束写成可重复执行的 CI 断言。

**仅支持 IPv4、TCP/UDP、源/目的端口、无状态、有序首次匹配和显式默认动作。** 报告的等价性只针对这个有限模型或明确指定的 scope；不等于真实设备、路由或端到端网络等价。“Proof”指在此模型内的符号判定及反例校验，不是经过证明助手验证的形式化证明。

不支持 IPv6、ICMP、NAT、连接跟踪、路由拓扑、完整厂商配置、云安全组状态语义、设备下发或真实流量采集。需要先由使用者把配置映射为这个模型；映射是否忠实，必须另行验证。

## 安装和验证

核心库的 MoonCakes 包名为 `hutingyu-nuist/moonpolicyproof`，与 GitHub 所有者一致。在现有 MoonBit 项目中添加依赖：

```sh
moon add hutingyu-nuist/moonpolicyproof@0.1.1
```

下述完整 CLI、浏览器演示和验证流程从 GitHub 源码运行。

需要 Git、Node.js 22 或更新版本，以及 MoonBit `moonc 0.10.4+2cc641edf`（CI 固定该版本及匹配 core）。

```sh
git clone https://github.com/hutingyu-nuist/moonpolicyproof.git
cd moonpolicyproof
moon update
node tools/verify.mjs
```

统一脚本检查格式、wasm-gc/wasm/js 的检查、构建和全部 32 个核心测试，以及 CLI 正负例、三个案例、浏览器 ABI 和公开接口漂移。默认仅对 native 做静态检查；有 C 编译器时执行 `node tools/verify.mjs --native`，CI 使用此模式实际运行 native 测试。32 是测试块数，不把循环样本数冒充独立测试数。

## 三个可复现的使用场景

先执行 `moon build --target js --deny-warn`。下列命令均在仓库根目录运行；产物路径对应默认 debug 构建。

### 1. 发布审查：检测网段意外放宽

平台工程师把允许 HTTPS 的源网段从 /24 改成 /16：

```sh
node _build/js/debug/build/cmd/main/main.js diff examples/01-change/before.policy examples/01-change/after.policy
```

预期退出码 **1**；报告包含新增放行的 `10.0.1.0 → 192.0.2.10 TCP / 443` 反例及前后命中结果，新增阻断为 null。若只核对原业务范围：

```sh
node _build/js/debug/build/cmd/main/main.js diff examples/01-change/before.policy examples/01-change/after.policy examples/01-change/business.scope
```

预期退出码 **0**，但报告保留非空 scope，**仅说明该范围内等价**。

### 2. 规则清理：识别联合遮蔽与部分生效

维护者输入两个 /25 前序规则，以及后面的 /24 和 /23 规则：

```sh
node _build/js/debug/build/cmd/main/main.js audit examples/02-shadow/policy.policy
```

预期退出码 **0**；四条规则依次为 `reachable, reachable, shadowed, partial`。完整遮蔽来自前两条规则的并集，不要求某一条单独覆盖后续规则。部分生效项同时提供可达包、被挡住的包及真正先命中的规则。

### 3. CI 回归：业务必须可达、管理端口必须隔离

应用团队提交策略和断言文件，在部署任务中执行：

```sh
node _build/js/debug/build/cmd/main/main.js check examples/03-regression/policy.policy examples/03-regression/good.assertions
node _build/js/debug/build/cmd/main/main.js check examples/03-regression/policy.policy examples/03-regression/bad.assertions
```

第一条预期退出码 **0**，覆盖 HTTPS、SSH 和协议隔离；第二条故意要求全网可访问 HTTPS，预期退出码 **1**，输出违反该要求的具体包。CI 必须检查退出码，不能把“生成了 JSON”当成断言通过。

一键复核三个场景：`node tools/examples.mjs`。案例文件与解释见 `examples/README.md`。

## 本地浏览器演示

```sh
moon build --target js --deny-warn
node tools/serve.mjs
```

打开终端显示的本地地址。界面在 Worker 中运行同一套 MoonBit 核心，无第三方脚本、上传或遥测；支持 scope、取消、30 秒终止，输入变化会清除旧结论。预览服务器只监听本机并使用固定文件白名单。详见 `web/README.md`。

## 策略格式与 API

```text
moonpolicyproof 1
default deny
rule web allow tcp 10.0.0.0/24 192.0.2.10/32 * 443
```

规则字段顺序：`rule ID allow|deny tcp|udp|any 源CIDR 目的CIDR 源端口 目的端口`。端口支持 `*`、单值、闭区间 `1000-2000`。严格 ASCII；允许整行 # 注释及空行。规则顺序不可交换；ID 唯一，默认动作只能在规则前出现一次。CIDR 主机位会规范化，导出不保留注释。scope 为规则的后五个匹配字段，没有动作；断言格式为 `assert ID allow|deny` 后接 scope。

库 API：`Policy::parse`、`evaluate`、`audit`、`find_scoped`、`compare`、`compare_scoped`、`check_assertions`。无 IO 的 `handle_request(String) -> (Int, String)` 接受 JSON 请求。公开签名见 `pkg.generated.mbti`。JSON schema 与稳定性见 `docs/architecture.md`。

| 退出码 | 含义 |
|---|---|
| 0 | 分析完成；diff 等价或 check 全部通过；audit 仅表示成功生成报告 |
| 1 | diff 存在语义差异，或 check 有失败断言 |
| 2 | 输入/格式/参数错误 |
| 3 | 资源预算耗尽，没有得出结论 |
| 4 | 内部反例回放校验失败，没有得出结论 |

## 可信边界与资源限制

每策略最多 256 规则、128 KiB ASCII、1024 行、每行 512 字符；最多 64 断言。BDD 默认保留 100000 节点，API 可在 2..200000 之间设置；每个上游操作最多 1000000 work，递归深度 128。JSON 请求限制 400000 字符、8 层嵌套。预算不是性能保证，BDD 最坏情况可能指数膨胀。资源或内部错误不输出部分成功报告。

测试包含 5 组区间各自穷举全部 65536 端口、12 个生成策略各 512 个五元组的独立解释器对照、双向差异穷举、联合遮蔽、边界输入及错误路径。反例回放可以发现反例生成错误，**不能单凭回放证明“没有遗漏反例”**；空集结论仍依赖编译器、BDD 和测试。详见 `SECURITY.md`。

## 生态位置、许可证和 AI 使用

检索 MoonCakes 及相关 GitHub 项目后，本项目选择复用已有库。`mooncidr`/`cidr-audit` 的单地址有序 ACL 与本项目有交集；`moonbdd` 提供通用布尔判定；`moon-flow-guard` 处理已观察流量。新增的是五字段全域首匹配编译与可回放变更工作流，而不是声称这些基础能力不存在。Batfish 已有更广泛的配置验证能力；本项目不替代它，面向可嵌入 MoonBit/JS 的小模型库。完整参考范围见 `THIRD_PARTY.md`。

Apache-2.0，见 LICENSE / NOTICE。AI 辅助了设计、实现、测试、文档和调试；不将 AI 作为人类贡献者。参赛者负责审核来源、理解算法、复现测试和维护；自动测试及 AI 辅助不能替代生产环境验证。未将真实用户配置、个人联系方式或申报材料放入仓库。
