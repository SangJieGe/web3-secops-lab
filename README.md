# Web3 SecOps Lab

一个用于学习 **Web3 安全运维（SecOps）** 的实验项目。

**长期目标**：学习并实践 Web3 安全运维、链上监控与安全事件响应。

**当前进度**：Week 1 ✅

---

## 当前状态（Week 1）

目前已经**真实实现并验证**的功能只有三件：

1. **程序启动** —— 可以通过 `python -m web3_secops.main` 启动。
2. **读取配置** —— 从环境变量或 `.env` 文件读取配置，缺失时回退到默认值。
3. **输出结构化日志** —— 每行输出一个 JSON 对象（JSON Lines 格式）。

> ⚠️ 本项目**没有**实现任何链上监控、智能合约审计、Wazuh 告警或生产级安全能力。
> 下文「后续规划」中的内容**尚未实现**。

---

## 目录结构

```
web3-secops-lab/
├── src/
│   └── web3_secops/
│       ├── __init__.py
│       └── main.py            # Week 1 主程序：启动 + 读配置 + 结构化日志
├── tests/
│   ├── __init__.py
│   └── test_main.py           # Week 1 测试
├── .env.example               # 环境配置示例
├── .gitignore
├── LICENSE
├── pyproject.toml             # 项目元数据、依赖、测试与 lint 配置
└── README.md
```

---

## 安装依赖

需要 Python **3.11** 或更高版本。

```bash
# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 安装（含开发依赖）
pip install -e ".[dev]"
```

---

## 配置

复制示例配置，按需修改：

```bash
cp .env.example .env
```

Week 1 只有两个配置项：

- `APP_NAME` —— 应用名称（默认 `web3-secops-lab`）
- `LOG_LEVEL` —— 日志级别（默认 `INFO`）

配置优先级：**真实环境变量 > `.env` 文件 > 代码内默认值**。

真实的 `.env` 文件已被 `.gitignore` 忽略，不会提交到 Git。

---

## 运行

```bash
python -m web3_secops.main
```

预期输出（每行一个 JSON）：

```json
{"ts": "...", "level": "INFO", "event": "startup", "app": "web3-secops-lab"}
{"ts": "...", "level": "INFO", "event": "config_loaded", "app_name": "web3-secops-lab", "log_level": "INFO"}
{"ts": "...", "level": "INFO", "event": "shutdown", "status": "ok"}
```

---

## 测试

```bash
pytest
```

测试覆盖 Week 1 的真实功能：配置读取（含默认值回退）、结构化日志输出、主流程执行。

代码检查：

```bash
ruff check .
```

---

## 后续规划

以下内容**尚未实现**，将在后续学习阶段逐步加入。列出仅为记录学习路线，不代表当前具备这些能力。

- ⏳ **Week 2：Ethereum JSON-RPC** —— 学习连接节点、调用只读 RPC 方法读取链上数据（例如查询最新区块号）。
- ⏳ **Week 3+：区块扫描** —— 遍历区块、读取交易。
- ⏳ **Week 4+：ERC-20 事件解码** —— 解析 `Transfer` / `Approval` 等事件日志。
- ⏳ **后续：链上安全检测** —— 识别异常交易模式。
- ⏳ **后续：Wazuh 集成** —— 把结构化日志接入 Wazuh 做告警。
- ⏳ **后续：部署** —— Docker / Docker Compose 部署。
- ⏳ **后续：智能合约审计** —— 合约安全分析。

---

## 许可证

MIT，详见 [LICENSE](LICENSE)。
