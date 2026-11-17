# 日切放行

> 遵守 `ops/底座生成前必读_效率与技术栈.md`。FastAPI + Vue 3 + SQLite，交付须 docker compose 一键起；库用 SQLite，不挂外置 Postgres。  
> **禁止同构换皮**：本仓主链路、表结构、接口与页面均独立，不得与其它仓共用同一套 `/api/items` 壳。

## 骨架一句话

业务日分区切片登记后裁决完整度，完整才放行下游，并与消费水位对账

## 驳回写边界（甲规则，2026-11-17 钉死锁定）

口径全文见 `docs/驳回边界说明.md`，后端常量与 `GET /api/policy`（只读、附 sha256 哈希）同源，当日无修改入口：

- 驳回路径对正式切片表 `slices` **零更新**：只改待审队列 `review_tickets` 的状态与驳回原因，回滚待审草稿（单据置「已驳回」，草稿永不合并）。
- 驳回事务连接安装 SQLite authorizer，对 `slices`/`releases`/`watermarks` 及一切 DDL 在引擎层 DENY；越权写整笔回滚、返回 403「驳回口径偏了」，并向 `audit_log(kind=deviation)` 留痕。
- 禁止驳回改正式切片行数或完整度，禁止驳回后推水位。
- 同单驳回/确认撞车：`BEGIN IMMEDIATE` 库级写锁串行，后手 409 并落 `conflict_queue`；正式行只有确认入口按合并规则可改。
- 候审列表、分区详情（`/api/partitions`）、冲突队列（`/api/conflicts`）、策略条（`/api/policy`）、处置页（`/api/audit`）五视图同源互证。
- 库仍为单机 SQLite（`data/app.db`），登录方式、端口、域名均不变。

## 基本信息

| 项 | 值 |
|----|-----|
| 产品名（首页） | 日切放行 |
| 目录 | `04-slicegate` |
| 领域建议 | 数仓与数据湖 |
| 接口 | http://127.0.0.1:10637 |
| 库 | `data/app.db` |
| 账号 | admin / 123456 |

## 为何能出多题

迟到切片、重切、跨分区依赖、部分完整冻结、消费水位回拨

## 避开

别做成作业拓扑编排换皮；别做成纯水位大盘

## 互斥切口候选

- 迟到切片整批拒收 vs 进待补齐冻结区
- 重切失败整笔回滚 vs 保留已完整分区
- 放行与水位同步闸 vs 异步放行后纠偏

## 启动（一键）

`powershell
cd projects/04-slicegate
docker compose up -d --build
`

浏览器：http://127.0.0.1:10637/  
健康检查：GET http://127.0.0.1:10637/api/health

本机开发（可选）：

`powershell
python -m pip install -r requirements.txt
python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 10601
python -m pytest -q
`
