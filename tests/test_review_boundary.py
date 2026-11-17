
import sqlite3
import pytest
from fastapi.testclient import TestClient
import app as appmod
from app import app, init_db, reject_authorizer, BOUNDARY_RULE_ID


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    init_db()
    yield


def _login(c, username="admin", password="123456"):
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _viewer(c):
    return _login(c, "viewer", "view123")


def _snapshot(c, headers):
    return {
        "slices": c.get("/api/slices", headers=headers).json()["items"],
        "releases": c.get("/api/releases", headers=headers).json()["items"],
        "watermarks": c.get("/api/watermarks", headers=headers).json()["items"],
    }


def _new_slice(c, headers, no, row_count=10, expected_count=100, partition="ut"):
    r = c.post("/api/slices", headers=headers, json={
        "slice_no": no, "biz_date": "2026-11-17", "partition_key": partition,
        "row_count": row_count, "expected_count": expected_count})
    assert r.status_code == 200, r.text
    return no


def _new_review(c, headers, slice_no=None,
                draft_row_count=1000, draft_expected_count=1000, note="重切补齐"):
    if slice_no is None:
        slice_no = _new_slice(c, headers, f"SL-UT-{len(c.get('/api/slices', headers=headers).json()['items'])}")
    r = c.post("/api/reviews", headers=headers, json={
        "slice_no": slice_no, "draft_row_count": draft_row_count,
        "draft_expected_count": draft_expected_count, "note": note})
    assert r.status_code == 200, r.text
    return r.json()["ticket_no"]


# ---------------------------------------------------------------------------
# 甲规则核心：驳回对正式切片表零更新，不推水位
# ---------------------------------------------------------------------------
def test_reject_zero_update_on_official_tables():
    c = TestClient(app)
    h = _login(c)
    ticket = _new_review(c, h)
    before = _snapshot(c, h)

    r = c.post(f"/api/reviews/{ticket}/reject", headers=h, json={"reason": "草稿口径不符，回滚草稿"})
    assert r.status_code == 200
    assert r.json()["status"] == "已驳回"

    after = _snapshot(c, h)
    # 正式切片表（行数/完整度/放行态）、放行流水、水位全部零变化
    assert after["slices"] == before["slices"]
    assert after["releases"] == before["releases"]
    assert after["watermarks"] == before["watermarks"]

    # 只改待审队列状态与原因，草稿随单作废
    rv = c.get("/api/reviews", headers=h).json()["items"]
    mine = next(x for x in rv if x["ticket_no"] == ticket)
    assert mine["status"] == "已驳回"
    assert mine["reject_reason"] == "草稿口径不符，回滚草稿"
    assert mine["decided_by"] == "admin"
    assert mine["version"] == 2

    # 驳回后再确认必须失败，草稿永远不得合并
    again = c.post(f"/api/reviews/{ticket}/confirm", headers=h)
    assert again.status_code == 409
    assert c.get("/api/slices", headers=h).json()["items"] == before["slices"]


def test_reject_requires_reason_and_admin():
    c = TestClient(app)
    h = _login(c)
    ticket = _new_review(c, h)

    empty = c.post(f"/api/reviews/{ticket}/reject", headers=h, json={"reason": "  "})
    assert empty.status_code == 400

    vh = _viewer(c)
    denied = c.post(f"/api/reviews/{ticket}/reject", headers=vh, json={"reason": "只读角色试驳回"})
    assert denied.status_code == 403
    # 被拒后正式行与单据状态都不动
    rv = c.get("/api/reviews", headers=h).json()["items"]
    assert next(x for x in rv if x["ticket_no"] == ticket)["status"] == "待审"


def test_authorizer_engine_gate_blocks_official_writes():
    """引擎层闸门：装上驳回 authorizer 后，正式写路径一律 DENY，白名单表可写。"""
    conn = sqlite3.connect(appmod.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.set_authorizer(reject_authorizer)
    conn.execute("BEGIN")
    for sql in [
        "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status)"
        " VALUES ('X','2026-11-17','z',1,1,'完整','未放行')",
        "UPDATE slices SET row_count=999 WHERE id=1",
        "DELETE FROM slices WHERE id=1",
        "INSERT INTO releases(slice_id,consumer,status,note,created_at) VALUES (1,'x','成功','x','t')",
        "INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES ('x','2026-11-17','t','x')",
        "CREATE TABLE evil(id INTEGER)",
    ]:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(sql)
    # 白名单内的写允许
    conn.execute("INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
                 " VALUES ('RV-X','admin','管理员','驳回','normal','review_tickets','ok','t')")
    conn.execute("UPDATE review_tickets SET status='已驳回' WHERE ticket_no='RV-20261117-001'")
    conn.rollback()
    conn.close()


def test_deviation_is_logged_when_gate_trips():
    """闸门拦截即偏离：直接触发 DENY 后由服务记 audit_log(kind=deviation) 的口径可核验。"""
    c = TestClient(app)
    h = _login(c)
    # 复用服务内部同一闸门与偏离记录器，验证偏离落库口径
    appmod.log_deviation("RV-20261117-001", "admin", "管理员", "模拟 authorizer DENY")
    audits = c.get("/api/audit", headers=h).json()
    dev = [a for a in audits["items"] if a["kind"] == "deviation"]
    assert dev and "驳回口径偏了" in dev[0]["detail"]
    assert audits["deviation_total"] == len(dev)
    pol = c.get("/api/policy", headers=h).json()
    assert pol["deviation_total"] == audits["deviation_total"]


def test_reject_endpoint_returns_403_and_logs_deviation_on_gate_trip(monkeypatch):
    """完整拦截链：驳回流程内一旦 authorizer DENY → 403「驳回口径偏了」+ 偏离留痕 + 单据/正式行不动。"""
    c = TestClient(app)
    h = _login(c)
    ticket = _new_review(c, h)
    before = c.get("/api/slices", headers=h).json()["items"]

    def paranoid(action, arg1, arg2, dbname, source):
        # 任何写都 DENY，模拟白名单被绕过/混驳乙规则的越权尝试
        if action in appmod._SQLITE_WRITE_ACTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    monkeypatch.setattr(appmod, "reject_authorizer", paranoid)

    r = c.post(f"/api/reviews/{ticket}/reject", headers=h, json={"reason": "越权尝试"})
    assert r.status_code == 403 and "驳回口径偏了" in r.json()["detail"]

    # 事务已回滚：单据仍是待审，正式表零变化
    rv = c.get("/api/reviews", headers=h).json()["items"]
    assert next(x for x in rv if x["ticket_no"] == ticket)["status"] == "待审"
    assert c.get("/api/slices", headers=h).json()["items"] == before

    audits = c.get("/api/audit", headers=h).json()["items"]
    dev = [a for a in audits if a["ticket_no"] == ticket and a["kind"] == "deviation"]
    assert dev and "驳回口径偏了" in dev[0]["detail"]


# ---------------------------------------------------------------------------
# 确认入口：唯一可按合并规则改正式行的路径，且不推水位
# ---------------------------------------------------------------------------
def test_confirm_merges_official_row_without_watermark():
    c = TestClient(app)
    h = _login(c)
    no = _new_slice(c, h, "SL-UT-CONF", row_count=10, expected_count=1000)
    ticket = _new_review(c, h, slice_no=no, draft_row_count=1000, draft_expected_count=1000)
    wm_before = len(c.get("/api/watermarks", headers=h).json()["items"])

    r = c.post(f"/api/reviews/{ticket}/confirm", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "已确认"

    sl = c.get("/api/slices", headers=h).json()["items"]
    target = next(s for s in sl if s["slice_no"] == no)
    assert target["row_count"] == 1000 and target["completeness"] == "完整"
    # 确认只合并正式行，不推水位
    assert len(c.get("/api/watermarks", headers=h).json()["items"]) == wm_before

    # 已确认单再驳回必须失败，驳回永远不能回改正式行
    again = c.post(f"/api/reviews/{ticket}/reject", headers=h, json={"reason": "迟来的驳回"})
    assert again.status_code == 409
    target2 = next(s for s in c.get("/api/slices", headers=h).json()["items"]
                   if s["slice_no"] == no)
    assert target2["row_count"] == 1000


def test_confirm_requires_admin():
    c = TestClient(app)
    h = _login(c)
    ticket = _new_review(c, h)
    vh = _viewer(c)
    assert c.post(f"/api/reviews/{ticket}/confirm", headers=vh).status_code == 403


# ---------------------------------------------------------------------------
# 撞车串行：同单驳回/确认并发，库级写锁 + 后手争用落冲突队列
# ---------------------------------------------------------------------------
def test_begin_immediate_serializes_writers():
    c1 = sqlite3.connect(appmod.DB_PATH, timeout=0.3)
    c2 = sqlite3.connect(appmod.DB_PATH, timeout=0.3)
    c1.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.OperationalError):
        c2.execute("BEGIN IMMEDIATE")  # 后手拿不到写锁
    c1.rollback()
    c2.execute("BEGIN IMMEDIATE")     # 先手释放后串行进入
    c2.rollback()
    c1.close(); c2.close()


def test_late_reject_after_decide_lands_in_conflict_queue():
    c = TestClient(app)
    h = _login(c)
    ticket = _new_review(c, h)
    assert c.post(f"/api/reviews/{ticket}/confirm", headers=h).status_code == 200

    # 后手驳回争用：409 + 冲突队列留痕，正式行不动
    r = c.post(f"/api/reviews/{ticket}/reject", headers=h, json={"reason": "撞车驳回"})
    assert r.status_code == 409
    cf = c.get("/api/conflicts", headers=h).json()["items"]
    hit = [x for x in cf if x["ticket_no"] == ticket]
    assert hit and hit[0]["winner_action"] == "已确认" and hit[0]["loser_action"] == "驳回"


def test_duplicate_pending_review_rejected():
    c = TestClient(app)
    h = _login(c)
    no = _new_slice(c, h, "SL-UT-DUP")
    _new_review(c, h, slice_no=no)
    r = c.post("/api/reviews", headers=h, json={
        "slice_no": no, "draft_row_count": 50, "draft_expected_count": 100, "note": "重复挂单"})
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# 五视图互证：候审列表 / 分区详情 / 冲突队列 / 策略条 / 处置页
# ---------------------------------------------------------------------------
def test_views_cross_corroborate():
    c = TestClient(app)
    h = _login(c)
    n1 = _new_slice(c, h, "SL-UT-V1", partition="v1")
    n2 = _new_slice(c, h, "SL-UT-V2", partition="v2")
    t1 = _new_review(c, h, slice_no=n1)
    t2 = _new_review(c, h, slice_no=n2, note="另一分区")
    c.post(f"/api/reviews/{t1}/reject", headers=h, json={"reason": "回滚草稿"})

    reviews = c.get("/api/reviews", headers=h).json()["items"]
    parts = c.get("/api/partitions", headers=h).json()
    conflicts = c.get("/api/conflicts", headers=h).json()["items"]
    policy = c.get("/api/policy", headers=h).json()
    audits = c.get("/api/audit", headers=h).json()["items"]

    # 分区详情计数 == 候审列表按状态统计
    for p in parts["items"]:
        same = [r for r in reviews if r["draft_slice_no"] == p["slice_no"]]
        assert p["pending_cnt"] == sum(1 for r in same if r["status"] == "待审")
        assert p["rejected_cnt"] == sum(1 for r in same if r["status"] == "已驳回")
        assert p["confirmed_cnt"] == sum(1 for r in same if r["status"] == "已确认")
    assert parts["pending_total"] == sum(1 for r in reviews if r["status"] == "待审")
    assert parts["conflict_total"] == len(conflicts) == policy["conflict_total"]

    # 策略条：甲规则钉死、当日锁定、只读无修改入口、哈希在案
    assert policy["rule_id"] == BOUNDARY_RULE_ID == "甲"
    assert policy["locked"] is True and policy["locked_date"] == "2026-11-17"
    assert set(policy["forbidden_tables"]) == {"slices", "releases", "watermarks"}
    assert "review_tickets" in policy["writable_tables"]
    assert len(policy["boundary_hash"]) == 64

    # 处置页留得住驳回痕迹，且口径写明正式表零更新
    rej_logs = [a for a in audits if a["ticket_no"] == t1 and a["action"] == "驳回"]
    assert rej_logs and "零更新" in rej_logs[0]["detail"]
    # t2 仍待审，两处视图一致
    assert parts["pending_total"] >= 1
    assert any(r["ticket_no"] == t2 and r["status"] == "待审" for r in reviews)


def test_init_db_migrates_legacy_database_without_touching_slices(tmp_path):
    """老库（只有 slices/releases/watermarks/users）启动迁移：加新表、不动正式行。"""
    legacy = tmp_path / "legacy.db"
    src = sqlite3.connect(legacy)
    src.executescript("""
    CREATE TABLE users(username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL);
    INSERT INTO users VALUES ('admin','x','管理员');
    CREATE TABLE slices(id INTEGER PRIMARY KEY AUTOINCREMENT, slice_no TEXT UNIQUE NOT NULL,
      biz_date TEXT NOT NULL, partition_key TEXT NOT NULL, row_count INTEGER NOT NULL,
      expected_count INTEGER NOT NULL, completeness TEXT NOT NULL, release_status TEXT NOT NULL);
    INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status)
      VALUES ('SL-OLD','2026-11-10','old',7,10,'部分完整','未放行');
    CREATE TABLE releases(id INTEGER PRIMARY KEY AUTOINCREMENT, slice_id INTEGER, consumer TEXT,
      status TEXT, note TEXT, created_at TEXT);
    CREATE TABLE watermarks(id INTEGER PRIMARY KEY AUTOINCREMENT, consumer TEXT, biz_date TEXT,
      watermark TEXT, source_slice TEXT);
    """)
    src.commit(); src.close()

    appmod.DB_PATH = legacy
    try:
        appmod.init_db()
        c = sqlite3.connect(legacy)
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"review_tickets", "conflict_queue", "audit_log"} <= tables
        row = c.execute("SELECT row_count, completeness, release_status FROM slices WHERE slice_no='SL-OLD'").fetchone()
        assert row == (7, "部分完整", "未放行")  # 正式行原样
        c.close()
    finally:
        appmod.DB_PATH = tmp_path / "t.db"


def test_legacy_pipeline_unchanged_and_login_still_works():
    # 登录方式照旧：admin/123456
    c = TestClient(app)
    h = _login(c)
    assert c.get("/api/health").json()["product"] == "日切放行"
    # 既有主链路：部分完整禁止放行
    assert c.post("/api/slices/1/release", headers=h, json={"consumer": "x"}).status_code == 409
    ok = c.post("/api/slices", headers=h, json={
        "slice_no": "SL-T-1", "biz_date": "2026-11-04", "partition_key": "mid",
        "row_count": 10, "expected_count": 10})
    sid = ok.json()["id"]
    assert c.post(f"/api/slices/{sid}/release", headers=h, json={"consumer": "ads_x"}).status_code == 200
    wm = c.get("/api/watermarks", headers=h).json()["items"]
    assert any(w["source_slice"] == "SL-T-1" for w in wm)
