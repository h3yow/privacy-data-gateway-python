# Privacy Data Gateway

在 HTTP 服务上提供**分级呈现、规则热切换、审计一致**的隐私数据访问能力。

## 授权模型

- **主体（Subject）**：由 `X-Subject-Id` 请求头标识，持有授权级别 `level`（整数，越大可见性越高）与过期时间 `expires_at`。
- **字段档位**：规则为每个敏感字段配置 `{最低级别: 呈现方式}`，呈现方式三档：
  - `PLAIN` 明文、`MASKED` 确定性脱敏（保留首尾、中间置 `*`）、`HIDDEN` 不出现。
  - 判定取主体级别**可达的最高档位**；级别 ≤ 0 直接拒绝。
- **拒绝原因可区分**（响应 `reason` 字段）：

| reason | 含义 |
|---|---|
| `SUBJECT_UNKNOWN` | 主体不存在（未授权） |
| `GRANT_EXPIRED` | 授权已过期 |
| `RESOURCE_NOT_FOUND` | 记录不存在 |
| `INSUFFICIENT_LEVEL` | 授权级别不足（level ≤ 0） |
| `AUDIT_FAILURE` | 审计写入失败，访问一并失败（HTTP 500） |

**确定性**：呈现结果只取决于 `(主体授权, 记录内容, 规则版本)`；字段按名排序遍历、脱敏函数为纯函数，与请求顺序、并发、缓存无关。

## 规则版本语义

- 规则以**不可变 `RuleSet`** 表示，含 `version`、`field_modes`、`retention_days`（留存天数元数据）。
- `RuleRegistry.publish()` 以单次引用替换**原子切换**；`GatewayService.access()` 进入时取一次快照，**整次请求只用一个版本**，切换期间的并发请求各自持有完整旧版或新版，绝不混用。
- 切换后新请求按新版本判定；**历史审计事件与导出结果记录当时所用版本号与呈现结果，永不改写**。复现方式：用同一版本号的 `RuleSet` 重新构造服务重放请求，结果与历史审计一致（见 `test_old_audit_entries_remain_reproducible`）。

## 审计语义

- 允许与拒绝**都**产生 `AuditEvent`：序号、时间、主体、记录、规则版本、结果标记与呈现结果（判定依据）。
- **成败一致**：先写审计再给结论；审计写失败时访问返回 `AUDIT_FAILURE`、不放行任何数据、不留半成品记录。审计汇故障恢复后访问自动恢复。
- `GET /audit` 导出全部审计痕迹，内容随规则版本固定、可复现。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/records/{id}` | 按 `X-Subject-Id` 的授权级别呈现记录 |
| POST | `/rules` | 运行中原子发布新规则版本 |
| GET | `/audit` | 导出审计痕迹 |

## 验证方法

```bash
uv run pytest            # 全部 20 个测试，日志打印输入与判定依据
uv run uvicorn main:app  # 启动服务
```

测试覆盖（`tests/`）：

- `test_access_levels.py`：各授权级别呈现、四种拒绝原因区分、呈现确定性；
- `test_rule_switching.py`：规则中途切换、旧审计结论复现、8 线程并发切换不混用版本；
- `test_audit.py`：允许/拒绝均留痕、审计失败不放行且无残留、并发序号唯一；
- `test_http_api.py`：HTTP 端到端（访问、热切换、审计导出）。
