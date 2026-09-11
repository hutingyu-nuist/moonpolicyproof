# 架构与可信计算边界

## 分层

1. `ports/model/parser`：有界端口、不可变策略快照、ASCII DSL。Policy 的规则数组是私有字段，避免外部调用者绕过 256 条与唯一 ID 约束。
2. `evaluate`：只使用标量比较与 CIDR contains，逐规则返回首次命中，不调用 BDD。
3. `symbolic/compile`：一个请求创建一个私有 Manager，不导出 BDD 句柄，禁止跨 manager 混用。
4. `diff/audit/scope/assertions`：集合运算与证据生成；解码后再调用第二层检查前后动作、scope 与命中规则。
5. `report/request`：版本化 JSON 与退出码；任何错误撤销整个请求的输出，不返回之前生成的部分成功结果。
6. `cmd/browser`：仅文件/进程/字符串桥接；CLI、浏览器与库共用同一核心。

## 97 位模型

变量按源 IPv4 32 位、目的 IPv4 32 位、协议 1 位（0 TCP / 1 UDP）、源端口 16 位、目的端口 16 位排列；各整数 MSB-first。全部位模式均对应模型内一个包。CIDR 约束前缀位；端口 [L,H] 编译为 ≤H 且非 ≤L−1，不枚举端口。

对于规则谓词 P_i，初始剩余域 R_0=true；有效域 E_i=R_i ∩ P_i，R_(i+1)=R_i ∩ ¬P_i。Allow 域是全部允许规则有效域的并，default allow 时还加最终剩余域。

新增放行=¬A_before ∩ A_after；新增阻断=A_before ∩ ¬A_after。scope 非空时分别与 scope 相交。完整遮蔽要求 E_i 为空；部分遮蔽要求 E_i 与 P_i∩¬E_i 都非空。前序 allow 与 deny 同样会阻止后续规则成为首次匹配。

## 结论与证据

BDD 为差异域返回一个满足赋值，解码后独立解释器必须回放出预期结果。每个方向最多输出一个例子，**不是完整变化列表、最小反例、业务严重程度排序或密码学证书**。首次满足赋值依赖变量顺序；调用者不能依赖固定 IP。

空集判定依赖 MoonBDD 正确性和本项目编译正确性。标量解释器对照在约化域穷举；端口区间对照遍历完整端口域。测试并非数学上的完备性证明。

## 请求与报告

`handle_request` 的 JSON 对象支持 command: help/format/audit/diff/check；未知字段拒绝。diff 需要 before/after，可选 scope；audit/format 需要 policy；check 需要 policy/assertions。max_nodes 可用于除 help 外的请求；库 API 中同名参数控制 manager 节点预算。

报告 schema 为 `moonpolicyproof.{comparison,diff,audit,assertions,format,help,error}.v1`。comparison 带 scope（全域为 null）及 result；diff 带 equivalent、新增放行/阻断及 retained_nodes。null 表示该域没有见证，不表示计算被跳过。错误报告只有 category/message，没有 equivalent。消费者须先检查退出码和 schema，不依赖 JSON 对象键顺序或调试错误文案。

v1 允许增加字段；删除字段、改变字段含义或扩大包模型须升级 schema。DSL header 也独立版本化。生成接口由 `moon info` 管理，验证脚本检查 drift。

## 预算

DSL 128 KiB ASCII / 1024 行 / 256 规则；断言文件 32 KiB / 128 行 / 64 条；行限制 512 字符；规则 ID 1..64 ASCII 字母数字下划线连字符。Scope 256 字符；JSON 400000 字符与 8 层嵌套。每次分析独立 manager：默认 100000、上限 200000 节点；cache 条目同节点预算；每次 BDD 操作 work 上限 1000000、depth 128。

上游 work 是**单次操作预算，不是整个请求累计 work 或毫秒预算**。规则/断言数量提供额外有限界限；生产 CI 应设置作业超时，浏览器单独 30 秒终止 Worker。预算耗尽不能转成“安全”“等价”或“断言通过”。
