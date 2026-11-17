
import hashlib, secrets, sqlite3
from datetime import date, datetime
from pathlib import Path
from fastapi import Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

# ---------------------------------------------------------------------------
# 驳回写边界：甲规则（二选一钉死，当天锁定，无任何修改入口）
# 口径与 docs/驳回边界说明.md 同源；/api/policy 只读返回并附校验哈希。
# ---------------------------------------------------------------------------
BOUNDARY_RULE_ID = "甲"
BOUNDARY_LOCKED_DATE = "2026-11-17"
BOUNDARY_TEXT = (
    "甲规则：驳回路径对正式切片表(slices)零更新，只改待审队列(review_tickets)状态与原因、"
    "回滚待审草稿，并可写 audit_log/conflict_queue；禁止写 releases、watermarks，"
    "禁止改正式切片行数或完整度，禁止驳回后推水位。越权写由 SQLite authorizer DENY 拦截，"
    "回滚并记 audit_log(kind=deviation)「驳回口径偏了」。"
)
BOUNDARY_HASH = hashlib.sha256(BOUNDARY_TEXT.encode("utf-8")).hexdigest()

# 驳回事务里只有这三张表允许写；其余表（slices/releases/watermarks/sqlite_master…）一律 DENY。
REJECT_WRITABLE_TABLES = frozenset({"review_tickets", "audit_log", "conflict_queue"})
_SQLITE_WRITE_ACTIONS = frozenset({
    sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_REINDEX,
})


def reject_authorizer(action, arg1, arg2, dbname, source):
    """装在驳回事务连接上的引擎级闸门：白名单之外的写操作全部 DENY。"""
    if action in _SQLITE_WRITE_ACTIONS and arg1 not in REJECT_WRITABLE_TABLES:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))


class LoginIn(BaseModel):
    username: str
    password: str


def require_user(authorization: str | None) -> tuple[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    with connect() as c:
        row = c.execute("SELECT role FROM users WHERE username=?", (u,)).fetchone()
    if not row:
        raise HTTPException(401, "登录已失效")
    return u, row["role"]


def require_admin(authorization: str | None) -> tuple[str, str]:
    username, role = require_user(authorization)
    if role != "管理员":
        raise HTTPException(403, "仅管理员可处置待审单")
    return username, role


def next_ticket_no(conn) -> str:
    prefix = "RV-" + date.today().strftime("%Y%m%d") + "-"
    n = conn.execute(
        "SELECT COUNT(*) c FROM review_tickets WHERE ticket_no LIKE ?", (prefix + "%",)
    ).fetchone()["c"] + 1
    return f"{prefix}{n:03d}"


def log_conflict(ticket_no: str, winner_action: str, loser_action: str, loser: str, detail: str):
    with connect() as c:
        c.execute(
            "INSERT INTO conflict_queue(ticket_no,winner_action,loser_action,loser,detail,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (ticket_no, winner_action, loser_action, loser, detail, now()),
        )
        c.commit()


def log_deviation(ticket_no: str, actor: str, role: str, detail: str):
    with connect() as c:
        c.execute(
            "INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, actor, role, "偏离", "deviation", "slices/releases/watermarks",
             "驳回口径偏了：" + detail, now()),
        )
        c.commit()


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PRODUCT = "日切放行"
SKELETON = "业务日分区切片登记后裁决完整度，完整才放行下游，并与消费水位对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS slices(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_no TEXT UNIQUE NOT NULL,
          biz_date TEXT NOT NULL,
          partition_key TEXT NOT NULL,
          row_count INTEGER NOT NULL,
          expected_count INTEGER NOT NULL,
          completeness TEXT NOT NULL,
          release_status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS releases(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          status TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS watermarks(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          consumer TEXT NOT NULL,
          biz_date TEXT NOT NULL,
          watermark TEXT NOT NULL,
          source_slice TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS review_tickets(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ticket_no TEXT UNIQUE NOT NULL,
          draft_slice_no TEXT NOT NULL,
          draft_row_count INTEGER NOT NULL,
          draft_expected_count INTEGER NOT NULL,
          note TEXT NOT NULL,
          status TEXT NOT NULL,
          reject_reason TEXT NOT NULL DEFAULT '',
          submitted_by TEXT NOT NULL,
          decided_by TEXT NOT NULL DEFAULT '',
          decided_at TEXT NOT NULL DEFAULT '',
          version INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conflict_queue(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ticket_no TEXT NOT NULL,
          winner_action TEXT NOT NULL,
          loser_action TEXT NOT NULL,
          loser TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ticket_no TEXT NOT NULL,
          actor TEXT NOT NULL,
          role TEXT NOT NULL,
          action TEXT NOT NULL,
          kind TEXT NOT NULL DEFAULT 'normal',
          target TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        if conn.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"] == 0:
            rows = [
                ("SL-2026-11-01-east", "2026-11-01", "east", 980, 1000, "部分完整", "未放行"),
                ("SL-2026-11-01-west", "2026-11-01", "west", 1000, 1000, "完整", "已放行"),
                ("SL-2026-11-02-east", "2026-11-02", "east", 0, 1000, "待检", "未放行"),
            ]
            for r in rows:
                conn.execute("INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)", r)
            conn.execute("INSERT INTO releases(slice_id,consumer,status,note,created_at) VALUES (2,'ads_order','成功','完整切片放行','2026-11-01T18:00:00')")
            conn.execute("INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES ('ads_order','2026-11-01','2026-11-01T18:00:00','SL-2026-11-01-west')")
        if conn.execute("SELECT COUNT(*) c FROM review_tickets").fetchone()["c"] == 0:
            conn.execute(
                "INSERT INTO review_tickets(ticket_no,draft_slice_no,draft_row_count,draft_expected_count,note,status,submitted_by,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("RV-20261117-001", "SL-2026-11-02-east", 1000, 1000, "迟到补齐后重切，申请合并", "待审", "admin", "2026-11-17T09:10:00"),
            )
            conn.execute(
                "INSERT INTO review_tickets(ticket_no,draft_slice_no,draft_row_count,draft_expected_count,note,status,reject_reason,submitted_by,decided_by,decided_at,version,created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("RV-20261117-002", "SL-2026-11-01-east", 1000, 1000, "重切登记待审", "已驳回",
                 "草稿与正式口径不符，回滚草稿", "admin", "admin", "2026-11-17T10:20:00", 2, "2026-11-17T09:40:00"),
            )
            conn.execute(
                "INSERT INTO conflict_queue(ticket_no,winner_action,loser_action,loser,detail,created_at)"
                " VALUES (?,?,?,?,?,?)",
                ("RV-20261117-002", "驳回", "确认", "admin", "同单驳回与确认撞车，后手确认争用失败，正式行未改", "2026-11-17T10:20:00"),
            )
            conn.execute(
                "INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("RV-20261117-002", "admin", "管理员", "驳回", "normal", "review_tickets",
                 "原因：草稿与正式口径不符；正式切片表零更新，草稿作废", "2026-11-17T10:20:00"),
            )


@app.on_event("startup")
def _start():
    init_db()


@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "slices": n, "db": str(DB_PATH)}


@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username, role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


# ---------------------------------------------------------------------------
# 正式切片表：既有主链路（登记/重裁/放行/水位），驳回路径不得触碰
# ---------------------------------------------------------------------------
@app.get("/api/slices")
def list_slices(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM slices ORDER BY id").fetchall()
    return {"items": [dict(r) for r in rows]}


class SliceIn(BaseModel):
    slice_no: str
    biz_date: str
    partition_key: str
    row_count: int
    expected_count: int


@app.post("/api/slices")
def add_slice(body: SliceIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    comp = "完整" if body.row_count >= body.expected_count and body.expected_count > 0 else ("部分完整" if body.row_count > 0 else "待检")
    with connect() as c:
        try:
            cur = c.execute(
                "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)",
                (body.slice_no, body.biz_date, body.partition_key, body.row_count, body.expected_count, comp, "未放行"),
            )
            return {"id": cur.lastrowid, "completeness": comp}
        except sqlite3.IntegrityError:
            raise HTTPException(409, "切片号已存在")


@app.post("/api/slices/{sid}/evaluate")
def evaluate(sid: int, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
        if not row:
            raise HTTPException(404, "切片不存在")
        comp = "完整" if row["row_count"] >= row["expected_count"] and row["expected_count"] > 0 else ("部分完整" if row["row_count"] > 0 else "待检")
        c.execute("UPDATE slices SET completeness=? WHERE id=?", (comp, sid))
    return {"id": sid, "completeness": comp}


class ReleaseIn(BaseModel):
    consumer: str


@app.post("/api/slices/{sid}/release")
def release(sid: int, body: ReleaseIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
        if not row:
            raise HTTPException(404, "切片不存在")
        if row["completeness"] != "完整":
            c.execute("INSERT INTO releases(slice_id,consumer,status,note,created_at) VALUES (?,?,?,?,?)",
                      (sid, body.consumer, "拒绝", "完整度未达标", now()))
            c.commit()
            raise HTTPException(409, "未完整禁止放行")
        c.execute("UPDATE slices SET release_status='已放行' WHERE id=?", (sid,))
        c.execute("INSERT INTO releases(slice_id,consumer,status,note,created_at) VALUES (?,?,?,?,?)",
                  (sid, body.consumer, "成功", "完整切片放行", now()))
        c.execute("INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES (?,?,?,?)",
                  (body.consumer, row["biz_date"], now(), row["slice_no"]))
    return {"ok": True}


@app.get("/api/releases")
def list_releases(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT r.*, s.slice_no FROM releases r JOIN slices s ON s.id=r.slice_id ORDER BY r.id DESC""").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/watermarks")
def list_wm(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM watermarks ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# 待审合并队列：提交 → 驳回（甲规则）/ 确认（唯一可改正式行的入口）
# ---------------------------------------------------------------------------
class ReviewIn(BaseModel):
    slice_no: str
    draft_row_count: int
    draft_expected_count: int
    note: str = ""


@app.post("/api/reviews")
def create_review(body: ReviewIn, authorization: str | None = Header(default=None)):
    username, role = require_user(authorization)
    if body.draft_row_count < 0 or body.draft_expected_count < 0:
        raise HTTPException(400, "草稿计数不能为负")
    with connect() as c:
        sl = c.execute("SELECT id FROM slices WHERE slice_no=?", (body.slice_no,)).fetchone()
        if not sl:
            raise HTTPException(404, "正式切片不存在，无法挂待审单")
        dup = c.execute(
            "SELECT id FROM review_tickets WHERE draft_slice_no=? AND status='待审'", (body.slice_no,)
        ).fetchone()
        if dup:
            raise HTTPException(409, "该切片已有待审单，先处置再提交")
        ticket_no = next_ticket_no(c)
        cur = c.execute(
            "INSERT INTO review_tickets(ticket_no,draft_slice_no,draft_row_count,draft_expected_count,note,status,submitted_by,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, body.slice_no, body.draft_row_count, body.draft_expected_count,
             body.note.strip(), "待审", username, now()),
        )
        c.execute(
            "INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, username, role, "提交", "normal", "review_tickets",
             f"草稿 {body.slice_no} {body.draft_row_count}/{body.draft_expected_count} 进待审", now()),
        )
        return {"id": cur.lastrowid, "ticket_no": ticket_no, "status": "待审"}


@app.get("/api/reviews")
def list_reviews(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""
            SELECT rt.*, s.biz_date, s.partition_key,
                   s.row_count AS official_row_count,
                   s.expected_count AS official_expected_count,
                   s.completeness AS official_completeness
            FROM review_tickets rt JOIN slices s ON s.slice_no = rt.draft_slice_no
            ORDER BY rt.id DESC""").fetchall()
    return {"items": [dict(r) for r in rows]}


class RejectIn(BaseModel):
    reason: str


@app.post("/api/reviews/{ticket_no}/reject")
def reject_review(ticket_no: str, body: RejectIn, authorization: str | None = Header(default=None)):
    """甲规则驳回：仅待审队列状态/原因 + 草稿作废，正式切片表零更新（authorizer 强制）。"""
    username, role = require_admin(authorization)
    reason = (body.reason or "").strip()
    if not reason:
        raise HTTPException(400, "驳回原因不能为空")
    conn = connect()
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            log_conflict(ticket_no, "确认/其他处置", "驳回", username, "写锁争用，后手驳回未取得库级写锁")
            raise HTTPException(409, "同一待审单正在处置，后手驳回争用失败")
        # 引擎级闸门：本事务对 slices/releases/watermarks 等正式写路径一律 DENY。
        conn.set_authorizer(reject_authorizer)
        row = conn.execute("SELECT * FROM review_tickets WHERE ticket_no=?", (ticket_no,)).fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(404, "待审单不存在")
        if row["status"] != "待审":
            conn.rollback()
            log_conflict(ticket_no, row["status"], "驳回", username,
                         f"待审单已是{row['status']}，后手驳回争用失败，正式行未改")
            raise HTTPException(409, f"待审单已是{row['status']}状态，驳回争用失败")
        # 白名单内写：只改待审队列状态与原因（草稿随单据作废，永不合并）。
        conn.execute(
            "UPDATE review_tickets SET status='已驳回', reject_reason=?, decided_by=?, decided_at=?, version=version+1 WHERE id=?",
            (reason, username, now(), row["id"]),
        )
        conn.execute(
            "INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, username, role, "驳回", "normal", "review_tickets",
             f"原因：{reason}；正式切片表零更新，草稿作废", now()),
        )
        conn.commit()
    except HTTPException:
        raise
    except sqlite3.DatabaseError as e:
        # authorizer DENY 或任何引擎级越权：回滚 + 记偏离，绝不放行该写。
        try:
            conn.rollback()
        except sqlite3.DatabaseError:
            pass
        log_deviation(ticket_no, username, role, str(e))
        raise HTTPException(403, "驳回口径偏了：驳回禁止写正式切片表/放行流水/水位，已拦截并记录")
    finally:
        try:
            conn.set_authorizer(None)
        except sqlite3.DatabaseError:
            pass
        conn.close()
    return {"ok": True, "ticket_no": ticket_no, "status": "已驳回"}


@app.post("/api/reviews/{ticket_no}/confirm")
def confirm_review(ticket_no: str, authorization: str | None = Header(default=None)):
    """确认入口：拿到写锁后按合并规则改正式行；这是唯一允许改正式切片行的处置路径。"""
    username, role = require_admin(authorization)
    conn = connect()
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            log_conflict(ticket_no, "驳回/其他处置", "确认", username, "写锁争用，后手确认未取得库级写锁")
            raise HTTPException(409, "同一待审单正在处置，后手确认争用失败")
        row = conn.execute("SELECT * FROM review_tickets WHERE ticket_no=?", (ticket_no,)).fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(404, "待审单不存在")
        if row["status"] != "待审":
            conn.rollback()
            log_conflict(ticket_no, row["status"], "确认", username,
                         f"待审单已是{row['status']}，后手确认争用失败，正式行未改")
            raise HTTPException(409, f"待审单已是{row['status']}状态，确认争用失败")
        sl = conn.execute("SELECT * FROM slices WHERE slice_no=?", (row["draft_slice_no"],)).fetchone()
        if not sl:
            conn.rollback()
            raise HTTPException(404, "正式切片不存在，合并中止")
        new_count, expected = row["draft_row_count"], row["draft_expected_count"]
        comp = "完整" if new_count >= expected and expected > 0 else ("部分完整" if new_count > 0 else "待检")
        conn.execute(
            "UPDATE slices SET row_count=?, expected_count=?, completeness=? WHERE id=?",
            (new_count, expected, comp, sl["id"]),
        )
        conn.execute(
            "UPDATE review_tickets SET status='已确认', decided_by=?, decided_at=?, version=version+1 WHERE id=?",
            (username, now(), row["id"]),
        )
        conn.execute(
            "INSERT INTO audit_log(ticket_no,actor,role,action,kind,target,detail,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, username, role, "确认", "normal", "slices",
             f"按合并规则更新正式行 {row['draft_slice_no']} {sl['row_count']}/{sl['expected_count']} -> {new_count}/{expected}（{comp}）；未推水位",
             now()),
        )
        conn.commit()
    except HTTPException:
        raise
    finally:
        conn.close()
    return {"ok": True, "ticket_no": ticket_no, "status": "已确认"}


# ---------------------------------------------------------------------------
# 互证视图：分区详情 / 冲突队列 / 策略条 / 处置页
# ---------------------------------------------------------------------------
@app.get("/api/partitions")
def partitions(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""
            SELECT s.id, s.slice_no, s.biz_date, s.partition_key,
                   s.row_count, s.expected_count, s.completeness, s.release_status,
                   (SELECT COUNT(*) FROM review_tickets rt WHERE rt.draft_slice_no=s.slice_no AND rt.status='待审')  AS pending_cnt,
                   (SELECT COUNT(*) FROM review_tickets rt WHERE rt.draft_slice_no=s.slice_no AND rt.status='已驳回') AS rejected_cnt,
                   (SELECT COUNT(*) FROM review_tickets rt WHERE rt.draft_slice_no=s.slice_no AND rt.status='已确认') AS confirmed_cnt
            FROM slices s ORDER BY s.id""").fetchall()
        pending_total = c.execute("SELECT COUNT(*) c FROM review_tickets WHERE status='待审'").fetchone()["c"]
        conflict_total = c.execute("SELECT COUNT(*) c FROM conflict_queue").fetchone()["c"]
        deviation_total = c.execute("SELECT COUNT(*) c FROM audit_log WHERE kind='deviation'").fetchone()["c"]
    return {
        "items": [dict(r) for r in rows],
        "pending_total": pending_total,
        "conflict_total": conflict_total,
        "deviation_total": deviation_total,
    }


@app.get("/api/conflicts")
def list_conflicts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM conflict_queue ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/audit")
def list_audit(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
        deviation_total = c.execute("SELECT COUNT(*) c FROM audit_log WHERE kind='deviation'").fetchone()["c"]
    return {"items": [dict(r) for r in rows], "deviation_total": deviation_total}


@app.get("/api/policy")
def policy(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        deviation_total = c.execute("SELECT COUNT(*) c FROM audit_log WHERE kind='deviation'").fetchone()["c"]
        conflict_total = c.execute("SELECT COUNT(*) c FROM conflict_queue").fetchone()["c"]
        pending_total = c.execute("SELECT COUNT(*) c FROM review_tickets WHERE status='待审'").fetchone()["c"]
    return {
        "rule_id": BOUNDARY_RULE_ID,
        "rule_name": "甲规则：驳回对正式切片表零更新",
        "boundary_text": BOUNDARY_TEXT,
        "boundary_hash": BOUNDARY_HASH,
        "locked_date": BOUNDARY_LOCKED_DATE,
        "locked": True,
        "writable_tables": sorted(REJECT_WRITABLE_TABLES),
        "forbidden_tables": ["slices", "releases", "watermarks"],
        "deviation_total": deviation_total,
        "conflict_total": conflict_total,
        "pending_total": pending_total,
    }


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
