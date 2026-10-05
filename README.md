# Privacy Data Gateway

在 HTTP 服务上提供**分级呈现、规则热切换、审计一致、规则历史回看、档案封存复核**的隐私数据访问能力。

## 授权模型

- **主体（Subject）**：由 `X-Subject-Id` 请求头标识，持有授权级别 `level`（整数，越大可见性越高）与过期时间 `expires_at`。
- **字段档位**：规则为每个敏感字段配置 `{最低级别: 呈现方式}`，呈现方式三档：
  - `PLAIN` 明文、`MASKED` 确定性脱敏（保留首尾、中间置 `*`）、`HIDDEN` 不出现。
  - 判定取主体级别**可达的最高档位**；级别 ≤ 0 直接拒绝。
- **拒绝原因可区分**（响应 `reason` 字段）：

| reason | HTTP 状态 | 含义 |
|---|---|---|
| `SUBJECT_UNKNOWN` | 401 | 主体不存在（未授权） |
| `GRANT_EXPIRED` | 403 | 授权已过期 |
| `INSUFFICIENT_LEVEL` | 403 | 授权级别不足 / 越权 |
| `RESOURCE_NOT_FOUND` | 200 + allowed=false | 实时访问的记录不存在 |
| `AUDIT_FAILURE` | 500 | 审计写入失败，操作一并失败 |
| `VERSION_NOT_FOUND` | 404 | 查询的历史规则版本不存在 |
| `ARCHIVE_NOT_FOUND` | 404 | 复核的封存档案不存在 |
| `VERSION_CONFLICT` | 409 | 发布被拒：版本号重复或回退（仅 POST /rules） |

**确定性**：呈现结果只取决于 `(主体授权, 记录内容, 规则版本)`；字段按名排序遍历、脱敏函数为纯函数，与请求顺序、并发、缓存无关。

## 规则版本语义与历史回看

- 规则以**不可变 `RuleSet`** 表示，构造时即对入参做防御性深拷贝并冻结，调用方事后修改入参不影响已发布版本；含 `version`、`field_modes`、`retention_days`。
- `RuleRegistry.publish()` 以单次引用替换**原子切换**；`access()` 进入时取一次快照，**整次请求只用一个版本**，切换期间的并发请求各自持有完整旧版或新版，绝不混用。
- **已发布版本只增、不改、不删**，全部按发布先后保留：
  - 新版本号必须**严格大于**最新已发布版本；重复或回退当场抛 `RuleVersionConflictError`（HTTP 409，`body.reason=VERSION_CONFLICT`），现行版本与历史均不变，调用方可明确识别为"被拒绝的发布"。
  - 按号查历史 `history_version(n)` 为 **O(1)** 字典查找；历史列表为定长分页切片，历史累积不拖垮查询与在线访问。
- 历史审计事件与导出记录当时所用版本号与呈现结果，永不改写；可用同版本 `RuleSet` 重放复现（`test_old_audit_entries_remain_reproducible`）。

## 封存档案与事后复核

面向合规的"整批封存 + 事后复核"流程（`gateway/archives.py`）：

- **封存** `POST /archives`（主体级别 ≥ 2）：把时间区间内发生过的访问/拒绝（`action=ACCESS` 审计事件）整批封存为一份固定 `Archive`。
  - 每条 `SealedEntry` 记录：序号、时间、主体与当时级别、记录、**规则版本号**、允许/拒绝、判定原因、呈现结果，并同时封存**记录原文快照**与**该版本规则快照**（档案内每版本一份）。
  - 封存之后规则继续发布、底层记录被增删改，**档案内容保持封存时原样**，不随之变化。
- **复核** `GET /archives/{id}/review`（级别 ≥ 2）：用封存的规则版本与主体级别，对当前底层数据**重算**并逐条比对：
  - 允许条目逐字段比呈现结果，差异记 `PRESENTATION`（含字段名、封存值、当前值）；
  - 结论翻转（记录消失/出现）记 `OUTCOME`；档案内规则快照与注册表留档不一致记 `RULE_DRIFT`；
  - 报告给出 `total/matched/mismatched` 及每条差异；**复核动作不修改档案、不产生新的访问判定、不影响实时访问**，可重复执行。
- 封存与复核**先写审计再落库/出报告**；审计写失败时整次操作失败：不产生半份档案、不放报告，原因统一为 `AUDIT_FAILURE`。

## 审计语义

- 允许与拒绝**都**产生 `AuditEvent`；历史查询（`HISTORY`）、封存（`SEAL`）、复核（`REVIEW`）动作也留痕，事件新增 `action` 与 `subject_level` 字段。
- **成败一致**：先写审计再给结论/执行副作用；审计写失败时操作返回 `AUDIT_FAILURE`，不放行数据、不保存档案、不留半成品。审计汇恢复后自动恢复。
- `GET /audit` 导出全部痕迹（含 `action`、`subject_level`），内容随规则版本固定、可复现。

## HTTP 接口

| 方法 | 路径 | 最低级别 | 说明 |
|---|---|---|---|
| GET | `/records/{id}` | 1 | 按授权级别呈现记录 |
| POST | `/rules` | —（管理动作） | 原子发布新规则版本；冲突 409 |
| GET | `/rules` | 1 | 按发布先后列出全部版本（`limit/offset` 分页） |
| GET | `/rules/{version}` | 1 | 查某历史版本完整配置；不存在 404 |
| POST | `/archives` | 2 | 封存时间区间内的访问/拒绝 |
| GET | `/archives` | 2 | 列出已封存档案 ID |
| GET | `/archives/{id}/review` | 2 | 事后复核，逐条给对得上/对不上及差异 |
| GET | `/audit` | —（运维导出） | 导出审计痕迹 |

非实时访问接口统一以 `{"ok": bool, "reason": ...}` 表达成败与可区分拒绝类型。

## 兼容范围

- **旧规则版本**：升级前已发布的 `RuleSet` 自动纳入历史（注册表初始化版本即历史首版）；规则对象新增的构造期冻结只影响新构造，行为与旧版完全一致。
- **旧审计事件 / 旧档案**：`AuditEvent.action` 默认 `"ACCESS"`、`subject_level` 默认 `None`。旧事件可正常封存；对缺少级别快照的旧允许条目，复核若无法重算会标为差异（`UNRECOMPUTABLE`）而非误判一致。旧版本服务产出的审计 JSON 字段是新版导出字段的子集。
- 原有 20 个测试全部保留并通过，无接口破坏性变更（`POST /rules` 成功响应额外含 `ok: true`）。

## 验证方法

```bash
uv run pytest             # 全部 50 个测试，--log-cli 打印每个用例的输入与判定依据
uv run uvicorn main:app   # 启动服务
```

端到端手验：

```bash
# 1) 产生访问痕迹
curl -s -H 'X-Subject-Id: clerk' localhost:8000/records/r1
# 2) 看规则历史 / 查旧版
curl -s -H 'X-Subject-Id: admin' localhost:8000/rules
curl -s -H 'X-Subject-Id: admin' localhost:8000/rules/1
# 3) 重复发布被拒（409）
curl -s -X POST localhost:8000/rules -H 'Content-Type: application/json' \
  -d '{"version":1,"field_modes":{}}'
# 4) 封存并复核
curl -s -X POST -H 'X-Subject-Id: admin' localhost:8000/archives \
  -H 'Content-Type: application/json' -d '{}'
curl -s -H 'X-Subject-Id: admin' localhost:8000/archives/archive-1/review
```

测试覆盖（`tests/`）：

- `test_access_levels.py`：各授权级别呈现、四种拒绝原因区分、呈现确定性；
- `test_rule_switching.py`：规则中途切换、旧审计结论复现、8 线程并发切换不混用版本；
- `test_rule_history.py`：历史有序保留、重复/回退发布被拒且历史不变、按号查 O(1)、
  定长分页、三千版本不退化、入参篡改不影响已发布版本、并发发布版本唯一严格递增、历史查询拒绝语义；
- `test_archives.py`：封存条目固定（规则/记录快照）、无漂移全匹配、记录篡改检出字段差异、
  规则演进后仍按封存版本复核、缺失记录事后出现检出 OUTCOME、复核不改档且不影响实时路径、
  越权/未知主体/档案不存在拒绝、审计失败中止封存/复核/历史查询、访问+切换+封存并发单版本自洽；
- `test_audit.py`：允许/拒绝均留痕、审计失败不放行且无残留、并发序号唯一；
- `test_http_api.py`：HTTP 端到端（访问、热切换、409 冲突、历史查询、封存复核、分级越权、审计导出）。
