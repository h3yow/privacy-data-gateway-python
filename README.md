# Privacy Data Gateway（隐私数据访问与脱敏网关）

在已有 FastAPI 服务之上构建的一层隐私数据访问网关，保证敏感数据在
**多主体、多授权级别、规则持续演进**的情况下，其可见性与审计结论
**始终一致、可解释、可复现**。

## 1. 授权模型

### 1.1 密级（ClearanceLevel）

| 级别 | 名称 |
| --- | --- |
| 0 | `PUBLIC` |
| 1 | `INTERNAL` |
| 2 | `CONFIDENTIAL` |
| 3 | `RESTRICTED` |

- 每个**主体（subject）**对每条**记录（record）**持有一份授权 `Grant`：
  `{subject_id, record_id, level, expires_at}`；`expires_at=None` 表示不过期。
- 每条记录有记录级门槛 `required_level`，主体密级低于门槛时整记录拒绝。
- 记录类型（`record_type`）下的每个敏感字段在规则版本中有一份
  `FieldPolicy {min_level, strategy, full_level}`，实现**分级呈现**：
  - `subject_level >= full_level`（若设置）→ 明文 `VISIBLE`；
  - `subject_level >= min_level` → 按策略脱敏（`PARTIAL` / `MASK` / `HASH`）；
  - 否则 → 字段整体隐藏（`REDACT`）。
  - 无策略的字段视为非敏感字段，明文呈现。

### 1.2 脱敏策略（MaskingStrategy）

| 策略 | 说明 | 示例 |
| --- | --- | --- |
| `VISIBLE` | 明文 | `13800001234` |
| `PARTIAL` | 保留前 3 后 4 | `138****1234` |
| `MASK` | 固定掩码 | `****` |
| `HASH` | 确定性 SHA-256 前缀（同值永远同哈希） | `sha256:04e7...` |
| `REDACT` | 字段移除 | `null` |

### 1.3 拒绝原因（四类，可区分）

判定按固定优先级执行，每种原因有独立错误码与 HTTP 状态码：

| 优先级 | 错误码 | HTTP | 含义 |
| --- | --- | --- | --- |
| 1 | `resource_not_found` | 404 | 资源不存在 |
| 2 | `unauthorized` | 403 | 主体没有该资源的授权 |
| 3 | `grant_expired` | 403 | 授权存在但已过期 |
| 4 | `clearance_insufficient` | 403 | 授权有效但密级不足 |

判定为**纯函数**：输入相同（主体、记录快照、授权快照、规则版本、时间）
输出必然相同，与请求顺序、缓存无关（见 `decision.py`，
对应测试 `test_presentation_is_deterministic_regardless_of_order`）。

## 2. 规则版本语义

- `RuleVersion` 是**不可变**对象：`{version, published_at, field_policies, retention}`。
- 运行中变更规则 = 调用 `RuleRegistry.publish()` **发布一个新版本**；
  版本号必须严格递增，切换在锁内原子完成，不存在半新半旧状态。
- **请求级快照隔离**：每次请求开始时抓取一次当前规则快照
  （`RuleRegistry.current_snapshot()`），整次判定（含审计写入）只使用
  这一个快照。因此规则切换窗口内的并发请求不会混用新旧两套规则。
  对应确定性并发测试：
  `tests/test_rule_switch.py::test_concurrent_requests_during_switch_never_mix_rules`
  （用事件栅栏把 8 个请求停在“已抓快照未判定”窗口内再发布 v2，
  断言 8 个结果全部依据 v1）。
- **历史版本永久保留**：`GET /admin/rules/{version}` 可查询任一版本；
  切换前已产生的审计结论与导出不受新规则影响。
- **留存规则（RetentionPolicy）** 同样版本化，历史版本的留存策略不变。

### 可复现性

- 每条审计条目固化判定时的完整依据：规则版本、规则发布时间、记录数据快照、
  字段策略快照、授权密级与过期时间、逐字段判定依据（`basis`）。
- `ReplayService.replay()` 用这些快照 + 历史规则版本重放判定；
  `verify()` 将重放结果与审计条目逐字段比对。即使底层数据事后被修改，
  历史结论仍可复现（见 `test_replay_immune_to_later_data_change`）。
- 导出物（`ExportService`）来源于审计快照，固化其 `rule_version`；
  同一 decision 重复导出返回同一份结果。

## 3. 审计与成败一致性

- 所有敏感访问（**允许与拒绝均包括**）都同步写入审计条目，条目包含：
  主体、记录、结果标记（`allow/deny`）、拒绝原因、规则版本、判定依据、
  以及复现所需的全部快照。
- **审计先于返回**：审计写入成功后才返回数据或拒绝；写入失败时抛出
  `audit_write_failed`（HTTP 500），**不静默放行、不产生不完整记录**。
  即使请求本身应被拒绝，审计失败也整体失败，不会退化成“拒绝但无审计”。
- 成功访问数与审计条目数严格一一对应
  （见 `test_access_succeeds_exactly_when_audit_written`）。

## 4. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/records/{record_id}?subject_id=...` | 按主体授权分级呈现记录 |
| POST | `/admin/rules` | 发布新规则版本（版本号递增） |
| GET | `/admin/rules/current` | 当前生效版本 |
| GET | `/admin/rules/{version}` | 查询历史规则版本 |
| POST | `/exports/{decision_id}` | 基于审计条目生成不可变导出 |
| GET | `/audit` | 列出全部审计条目 |
| GET | `/audit/{decision_id}/verify` | 重放并校验历史结论 |

拒绝响应体示例：

```json
{"error": "grant_expired", "message": "grant_expired: subject=dave record=rec-1"}
```

种子数据（启动即可用）：记录 `rec-1`（customer，记录级门槛 INTERNAL）；
主体 `alice=INTERNAL`、`bob=CONFIDENTIAL`、`carol=RESTRICTED`、
`dave=INTERNAL（已过期）`、`eve` 无授权。

## 5. 验证方法

```bash
# 运行全部测试（34 个），-s 可查看每个用例打印的输入与判定依据
uv run python -m pytest tests/ -s -v
```

测试矩阵：

| 测试文件 | 覆盖场景 |
| --- | --- |
| `tests/test_authorization.py` | 三级授权可见性、四类可区分拒绝原因、确定性（顺序无关）、审计依据 |
| `tests/test_rule_switch.py` | 规则中途切换、历史结论/导出不变、历史版本留存、并发不混用规则、留存策略版本化 |
| `tests/test_concurrent`（同上） | 切换窗口并发栅栏测试 + 切换后全部按新版 |
| `tests/test_audit_failure.py` | 审计失败阻断允许、阻断拒绝、成功数=审计数、HTTP 500 |
| `tests/test_replay.py` | 底层数据变更后历史结论仍可复现、拒绝判定可复现 |
| `tests/test_api.py` | 接口级发布/查询/导出/校验、404 处理 |
| `tests/test_masking.py` | 各脱敏策略与哈希确定性 |

每个用例都会在日志中打印**输入**（`access input: subject=... record=...`）
与**判定依据**（`decision basis: ... basis={...}`），以及用例内显式的
`[INPUT]` 行。

## 6. 代码结构

```
privacy_gateway/
  errors.py    # 可区分的领域错误（未授权/过期/不存在/密级不足/审计失败）
  models.py    # 密级、授权、记录、不可变规则版本、判定结果、审计条目
  store.py     # 记录与授权存储（线程安全）
  rules.py     # 规则注册表：当前版本原子切换 + 历史版本留存
  masking.py   # 确定性脱敏纯函数
  decision.py  # 纯函数判定引擎（分级呈现 + 可解释 basis）
  audit.py     # 同步审计写入（失败显式抛出）
  service.py   # 编排：抓快照 -> 判定 -> 审计先行 -> 返回
  export.py    # 不可变、可复现的导出
  replay.py    # 基于审计快照与历史版本的重放与校验
  app.py       # FastAPI 装配、路由、种子数据
main.py        # 入口
tests/         # 上述测试矩阵
```
