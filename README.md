# Privacy Data Gateway

在 HTTP 服务上提供**分级呈现、规则热切换、审计一致、规则历史回看、档案封存与事后复核**的隐私数据访问能力。

## 授权模型

- **主体（Subject）**：由 `X-Subject-Id` 请求头标识，持有授权级别 `level`（整数，越大可见性越高）与过期时间 `expires_at`。
- **字段档位**：规则为每个敏感字段配置 `{最低级别: 呈现方式}`，呈现方式三档：
  - `PLAIN` 明文、`MASKED` 确定性脱敏（保留首尾、中间置 `*`）、`HIDDEN` 不出现。
  - 判定取主体级别**可达的最高档位**；级别 ≤ 0 直接拒绝。
- **拒绝原因可区分**（响应 `reason` 字段）：

| reason | 含义 | 触发入口 |
|---|---|---|
| `SUBJECT_UNKNOWN` | 主体不存在（未授权） | 全部 |
| `GRANT_EXPIRED` | 授权已过期 | 全部 |
| `RESOURCE_NOT_FOUND` | 记录不存在 | 实时访问 |
| `INSUFFICIENT_LEVEL` | 授权级别不足（访问 level≤0；合规入口 level<2） | 全部 |
| `AUDIT_FAILURE` | 审计写入失败，操作一并失败（HTTP 500） | 全部 |
| `VERSION_CONFLICT` | 发布版本号重复或回退（HTTP 409） | `POST /rules` |
| `VERSION_NOT_FOUND` | 查询的历史规则版本不存在 | `GET /rules/{v}` |
| `ARCHIVE_NOT_FOUND` | 复核的封存档案不存在 | `GET /archives/{id}` |
| `ARCHIVE_EMPTY` | 封存时间窗内没有任何访问事件 | `POST /archives` |

合规入口（历史查询、封存、复核）要求主体存在、未过期且 **级别 ≥ 2**（`ComplianceService(compliance_level=...)` 可配置）。

**确定性**：呈现结果只取决于 `(主体授权, 记录内容, 规则版本)`；字段按名排序遍历、脱敏函数为纯函数，与请求顺序、并发、缓存无关。

## 规则版本语义

- 规则以**不可变 `RuleSet`** 表示，含 `version`、`field_modes`、`retention_days`。发布时注册表会深拷贝并用 `MappingProxyType` 冻结嵌套字典，发布者事后修改手里的原对象**改不到**已发布版本。
- **只追加的版本历史**：`RuleRegistry` 永久保留每一个已发布版本，绝不覆盖、改写或删除。
  - `publish()` 要求新版本号**严格大于**所有已发版本；重复用老版本号或往小里发，当场抛 `VersionConflictError`（HTTP 409 + `VERSION_CONFLICT`），注册表状态不变。
  - `snapshot()` 为 O(1) 引用读取，在线访问只取当前快照，**不触碰历史**；
  - `get_version(v)` 为 O(1) 哈希查找，`list_versions()` 为 O(版本数) 目录遍历。历史增长既不拖垮在线访问，也不让翻旧账变慢。
- `publish()` 以单次引用替换**原子切换**；`GatewayService.access()` 进入时取一次快照，**整次请求只用一个版本**，与封存/复核并发时各自持有完整确定版本，绝不混用新旧规则。
- 切换后新请求按新版本判定；**历史审计事件记录当时所用版本号与呈现结果，永不改写**。

## 规则历史回看

- `GET /rules`：按发布先后返回版本目录 `[{version, published_at}, ...]`。
- `GET /rules/{version}`：取某历史版本当时的完整配置（`field_modes`、`retention_days`）；不存在返回 `allowed=false / VERSION_NOT_FOUND`。
- 两个入口都是合规级只读操作，允许与拒绝都会写审计（`action=rule_history`）。

## 封存档案与事后复核

### 封存 `POST /archives`

- 请求体 `{"start": ISO|null, "end": ISO|null, "archive_id": 可选}`，时间窗为**左闭右开 `[start, end)`**，`null` 表示开放边界。
- 把窗内**敏感数据访问事件（允许与拒绝都算）**整批深拷贝固化成一份 `Archive`：
  - 每条 `ArchivedEntry` 记录判定依据：`subject_id / record_id / rule_version / allowed / reason / presented / subject_level`，并带规范化 SHA-256 **逐条指纹**；档案整体也有指纹。
  - 档案涉及的规则版本号随档案保存（`rule_versions`）。
- **原子性**：先在内存构造固化档案，审计事件写成功后档案才入库；审计失败返回 `AUDIT_FAILURE`，没有半成品档案。空时间窗返回 `ARCHIVE_EMPTY`。
- 封存后规则继续发布、记录内容被改、审计汇继续追加，**都不影响已封存档案**（档案不依赖这些可变源）。

### 复核 `GET /archives/{archive_id}`

- **只读**操作：不改档案、不影响实时访问；复核本身也写审计（`action=review`）。
- 用注册表里**按条目封存时版本号取出的历史规则**，以事件发生时刻对**当前**主体授权与记录内容重放同一份判定逻辑（实时访问与复核共用 `gateway.decision.evaluate`），再逐条比对。
- 每条结论 `verdict`：

| verdict | 含义 |
|---|---|
| `MATCH` | 与封存时完全一致 |
| `TAMPERED` | 档案条目自身指纹不匹配（存档被改过），并给出封存/重算指纹 |
| `VERSION_MISSING` | 复核所需历史规则版本不在注册表（正常只追加语义下不应出现） |
| `RESOURCE_MISSING` | 底层记录已不存在 |
| `SUBJECT_CHANGED` | 主体已不存在/已过期，或授权级别相对封存时发生变化 |
| `PRESENTATION_DIFF` | 判定结果或逐字段呈现不同，`diff` 给出字段级 `{sealed, current}` 差异 |

- 报告汇总 `total/matched/mismatched/consistent`，`consistent=true` 仅当全部 MATCH。

## 审计语义

- 允许与拒绝**都**产生 `AuditEvent`：序号、时间、主体、记录、规则版本、结果标记、呈现结果、主体级别，以及操作类型 `action`（`access|rule_history|seal|review`）与关联的 `archive_id`。
- **成败一致且全局统一**：实时访问与三个合规入口都先写审计再给结论（`GatewayService.write_audit_event` 统一分配序号）。审计写失败时一律 `AUDIT_FAILURE`、不放任何数据、封存不落库、复核不出报告、不留半成品记录。审计汇恢复后操作自动恢复。
- `GET /audit` 导出全部审计痕迹（含合规元操作）。注意：封存档案只固化 `action=access` 的数据访问事件，合规元操作留在审计汇但不进档案。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/records/{id}` | 按 `X-Subject-Id` 的授权级别呈现记录 |
| POST | `/rules` | 原子发布新规则版本；版本号冲突返回 **409** |
| GET | `/rules` | 列全部历史版本目录（合规级） |
| GET | `/rules/{version}` | 取某历史版本完整配置（合规级） |
| POST | `/archives` | 封存时间窗内的访问/拒绝为固定档案（合规级，201） |
| GET | `/archives/{id}` | 只读复核档案，逐条给 MATCH/差异（合规级） |
| GET | `/audit` | 导出审计痕迹 |

网关自身的判定类拒绝沿用既有约定：**HTTP 200 + 响应体 `allowed=false` + 可区分 `reason`**；`VERSION_CONFLICT` 用 409、审计失败用 500。

## 与旧版本/旧档案的兼容范围

- **向后兼容**：原有 `GET /records`、`POST /rules`（发布更大版本号）、`GET /audit` 的请求与响应字段保持不变；`AuditEvent` 仅新增了**带默认值**的 `action / archive_id / subject_level` 字段，旧代码构造/读取不受影响。
- 初始规则版本仍为 1；升级后既有注册表只有当前版本一个历史点，从升级之后发布的版本才开始累积完整历史。
- 档案是本次新增能力：升级前不存在档案；历史审计事件可通过 `POST /archives` 按时间窗追溯封存（只要事件仍在审计汇中）。
- 旧档案（若由本系统更早导出）缺少逐条指纹时，复核会以封存内容重新计算指纹比对；本次版本产生的档案全部自带指纹。
- `RecordStore` 新增 `upsert/delete`（仅用于装配与构造数据漂移场景），不改变既有 `get` 行为。

## 验证方法

```bash
uv run pytest            # 全部 56 个测试，日志打印每个用例的输入与判定依据
uv run uvicorn main:app  # 启动服务
```

手工验证主链路：

```bash
# 1) 实时访问（v1）
curl -s localhost:8000/records/r1 -H 'X-Subject-Id: clerk'
# 2) 发布被拒：重复版本号 -> 409 VERSION_CONFLICT
curl -s -X POST localhost:8000/rules -H 'Content-Type: application/json' \
  -d '{"version":1,"field_modes":{"name":{"1":"PLAIN"}},"retention_days":7}'
# 3) 列历史 / 翻旧账
curl -s localhost:8000/rules -H 'X-Subject-Id: admin'
curl -s localhost:8000/rules/1 -H 'X-Subject-Id: admin'
# 4) 封存到目前为止的全部访问
curl -s -X POST localhost:8000/archives -H 'X-Subject-Id: admin' \
  -H 'Content-Type: application/json' -d '{"archive_id":"arc-1"}'
# 5) 复核（应 consistent=true）；改动底层数据后再复核即出现逐条差异
curl -s localhost:8000/archives/arc-1 -H 'X-Subject-Id: admin'
```

测试覆盖（`tests/`）：

- `test_access_levels.py`：各授权级别呈现、四种拒绝原因区分、呈现确定性；
- `test_rule_switching.py`：规则中途切换、旧审计结论复现、8 线程并发切换不混用版本；
- `test_audit.py`：允许/拒绝均留痕、审计失败不放行且无残留、并发序号唯一；
- `test_http_api.py`：原有 HTTP 端到端（访问、热切换、审计导出）；
- `test_rule_history.py`：版本按序留存与 O(1) 回查、重复/回退发布被拒、发布即冻结不可改、历史增长不拖垮在线访问、合规入口拒绝语义与留痕；
- `test_archive.py`：封存判定依据与指纹、时间窗半开、空窗/越权拒绝、规则演进与数据变更下档案不变、跨版本封存、复核 MATCH/呈现差异/记录缺失/提权/篡改/档案不存在、复核只读不影响实时访问、按封存版本重放、审计失败中止封存与复核、切换+封存+访问并发不串版；
- `test_compliance_http.py`：新入口 HTTP 端到端（409、历史查询、封存复核、各种可区分拒绝、审计失败 500）。
