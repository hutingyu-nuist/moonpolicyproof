# 来源、依赖与范围

本项目是对已有 MoonBit 生态能力的组合及实质语义扩展，不是移植 Batfish，也没有复制第三方算法实现文件到仓库。

| 项目 | 固定版本/许可证 | 实际用途或参考范围 |
|---|---|---|
| [MoonBDD](https://github.com/oyjh0381/MoonBDD) / oyjh0381/moonbdd | 0.1.0 / Apache-2.0 | 运行时依赖；ROBDD、布尔运算、SAT witness、节点/cache/work/depth 预算。未重写其 manager 或 canonicalization。 |
| [cidr-audit](https://github.com/BeiLaDuo/mooncidr-audit) / BeiLaDuo/cidr-audit | 0.1.2 / Apache-2.0 | 运行时依赖；IPv4/CIDR 解析、规范化、包含判断。未复制其 ACL 审计或文本 diff。 |
| [moonbitlang/async](https://github.com/moonbitlang/async) | 0.20.6 / Apache-2.0 | MoonBDD manifest 声明的传递依赖；本项目核心不调用其异步或 IO API。 |
| [MoonBit core](https://github.com/moonbitlang/core) | 与固定编译器匹配 / Apache-2.0 | JSON、标准类型、调试与集合。 |
| [Batfish](https://github.com/batfish/batfish) | Apache-2.0；非运行时依赖 | 阅读 README 与 filter 分析文档用于能力对比；已有更广的离线配置/ACL 分析，未移植其解析器、拓扑或求解实现。 |
| [mooncidr](https://github.com/lzh123411/21341)、[moon-flow-guard](https://github.com/wcj12314/1231) | 仅查重与公开 API/README 对比 | 前者单地址 ACL，后者已观察流量分析；没有引入源码或数据。 |

新增实现：97 位五元组谓词编译、规则剩余域推进、双向差异、独立解释器回放、联合遮蔽、scope/断言、报告协议、CLI 和浏览器桥接。最接近的库没有被表述为“完全无关”；差异在新增组合语义与可验收工作流。

依赖由 MoonCakes 下载，保留在被忽略的 .mooncakes 下，版权与许可证随原包保留。根 LICENSE 为 Apache-2.0 标准许可文本，NOTICE 标明本项目版权与直接依赖；测试及案例为本项目构造的合成数据，不来自真实网络。AI 辅助情况见 README。
