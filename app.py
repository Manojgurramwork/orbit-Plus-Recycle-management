from __future__ import annotations

import json
import hashlib
import hmac
import mimetypes
import os
import re
import secrets
import sqlite3
import uuid
from http.cookies import SimpleCookie
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SCRAP_APP_DATA_DIR", ROOT / "facility-data")).resolve()
UPLOAD_DIR = DATA_DIR / "documents"
DB_PATH = DATA_DIR / "facility.sqlite3"
MAX_BODY = 12 * 1024 * 1024
MIME_EXT = {"image/jpeg": ".jpg", "image/png": ".png", "application/pdf": ".pdf", "image/webp": ".webp"}
STATIC_TYPES = {
    "/app.css": "text/css; charset=utf-8",
    "/app.js": "text/javascript; charset=utf-8",
    "/orbitplus-logo.png": "image/png",
    "/montserrat-variable.ttf": "font/ttf",
    "/Montserrat-OFL.txt": "text/plain; charset=utf-8",
    "/grade-import-template.csv": "text/csv; charset=utf-8",
}
PASSWORD_ITERATIONS = 310_000
SESSION_MAX_AGE = 12 * 60 * 60
ALLOWED_ROLES = {"owner", "operations", "finance", "viewer"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def conn():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode = WAL")
    return c


def initialize():
    with conn() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS suppliers (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grades (
          id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
          polymer TEXT NOT NULL, form TEXT NOT NULL, color TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lots (
          id TEXT PRIMARY KEY, lot_code TEXT NOT NULL UNIQUE, grade_id TEXT NOT NULL REFERENCES grades(id),
          source_type TEXT NOT NULL, source_id TEXT NOT NULL, created_at TEXT NOT NULL,
          initial_qty_g INTEGER NOT NULL, cost_per_kg_paise INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'available'
        );
        CREATE TABLE IF NOT EXISTS stock_events (
          id TEXT PRIMARY KEY, lot_id TEXT NOT NULL REFERENCES lots(id), event_type TEXT NOT NULL,
          delta_g INTEGER NOT NULL, source_type TEXT NOT NULL, source_id TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS receipts (
          id TEXT PRIMARY KEY, receipt_code TEXT NOT NULL UNIQUE, supplier_id TEXT NOT NULL REFERENCES suppliers(id),
          grade_id TEXT NOT NULL REFERENCES grades(id), lot_id TEXT NOT NULL REFERENCES lots(id), vehicle_no TEXT NOT NULL,
          gross_g INTEGER NOT NULL, tare_g INTEGER NOT NULL, accepted_g INTEGER NOT NULL, rate_paise INTEGER NOT NULL,
          invoice_total_paise INTEGER NOT NULL, invoice_status TEXT NOT NULL, invoice_doc TEXT NOT NULL DEFAULT '',
          scale_ticket TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS machines (
          id TEXT PRIMARY KEY, machine_code TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
          process_area TEXT NOT NULL, rated_power_kw_milli INTEGER NOT NULL DEFAULT 0 CHECK(rated_power_kw_milli >= 0),
          machine_cost_per_hour_paise INTEGER NOT NULL DEFAULT 0 CHECK(machine_cost_per_hour_paise >= 0),
          electricity_rate_paise_per_kwh INTEGER NOT NULL DEFAULT 0 CHECK(electricity_rate_paise_per_kwh >= 0),
          active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), notes TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS production_runs (
          id TEXT PRIMARY KEY, run_code TEXT NOT NULL UNIQUE, input_lot_id TEXT NOT NULL REFERENCES lots(id),
          output_lot_id TEXT NOT NULL REFERENCES lots(id), output_grade_id TEXT NOT NULL REFERENCES grades(id),
          input_g INTEGER NOT NULL, output_g INTEGER NOT NULL, loss_g INTEGER NOT NULL, labor_paise INTEGER NOT NULL,
          energy_paise INTEGER NOT NULL, material_cost_paise INTEGER NOT NULL, total_cost_paise INTEGER NOT NULL,
          occurred_at TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
          machine_id TEXT REFERENCES machines(id), machine_label TEXT NOT NULL DEFAULT '',
          machine_hours_milli INTEGER NOT NULL DEFAULT 0 CHECK(machine_hours_milli >= 0),
          machine_cost_per_hour_paise INTEGER NOT NULL DEFAULT 0 CHECK(machine_cost_per_hour_paise >= 0),
          machine_cost_paise INTEGER NOT NULL DEFAULT 0 CHECK(machine_cost_paise >= 0),
          energy_kwh_milli INTEGER NOT NULL DEFAULT 0 CHECK(energy_kwh_milli >= 0),
          electricity_rate_paise_per_kwh INTEGER NOT NULL DEFAULT 0 CHECK(electricity_rate_paise_per_kwh >= 0)
        );
        CREATE TABLE IF NOT EXISTS customers (
          id TEXT PRIMARY KEY, customer_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL, contact_name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
          email TEXT NOT NULL DEFAULT '', gstin TEXT NOT NULL DEFAULT '', billing_address TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sales (
          id TEXT PRIMARY KEY, sale_code TEXT NOT NULL UNIQUE, customer_name TEXT NOT NULL, lot_id TEXT NOT NULL REFERENCES lots(id),
          quantity_g INTEGER NOT NULL, rate_paise INTEGER NOT NULL, invoice_total_paise INTEGER NOT NULL,
          cogs_paise INTEGER NOT NULL, invoice_doc TEXT NOT NULL DEFAULT '', vehicle_no TEXT NOT NULL DEFAULT '',
          occurred_at TEXT NOT NULL, created_at TEXT NOT NULL, customer_id TEXT REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          id TEXT PRIMARY KEY, event_type TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
          detail_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_stock_events_lot ON stock_events(lot_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_receipts_date ON receipts(occurred_at);
        CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(occurred_at);
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('owner','operations','finance','viewer')),
          password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS login_attempts (
          attempt_key TEXT PRIMARY KEY, failure_count INTEGER NOT NULL, window_started TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS employees (
          id TEXT PRIMARY KEY, employee_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL, job_title TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '',
          hourly_rate_paise INTEGER NOT NULL DEFAULT 0 CHECK(hourly_rate_paise >= 0),
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS time_entries (
          id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES employees(id),
          work_date TEXT NOT NULL, shift_label TEXT NOT NULL,
          clock_in_at TEXT NOT NULL, clock_out_at TEXT NOT NULL,
          break_minutes INTEGER NOT NULL DEFAULT 0, minutes_worked INTEGER NOT NULL,
          hourly_rate_paise INTEGER NOT NULL, labor_cost_paise INTEGER NOT NULL,
          note TEXT NOT NULL DEFAULT '', recorded_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
          UNIQUE(employee_id,work_date,shift_label)
        );
        CREATE INDEX IF NOT EXISTS idx_time_entries_date ON time_entries(work_date,clock_in_at);
        CREATE TABLE IF NOT EXISTS contractors (
          id TEXT PRIMARY KEY, contractor_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL, contact_name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labor_contracts (
          id TEXT PRIMARY KEY, contract_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
          contractor_id TEXT NOT NULL REFERENCES contractors(id), activity_type TEXT NOT NULL,
          pay_basis TEXT NOT NULL CHECK(pay_basis IN ('input_kg','output_kg','output_ton','shift','day','bale','fixed_job','invoice')),
          rate_paise INTEGER NOT NULL CHECK(rate_paise >= 0), valid_from TEXT NOT NULL, valid_to TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labor_work (
          id TEXT PRIMARY KEY, work_code TEXT NOT NULL UNIQUE,
          contractor_id TEXT NOT NULL REFERENCES contractors(id), contract_id TEXT NOT NULL REFERENCES labor_contracts(id),
          production_run_id TEXT REFERENCES production_runs(id), work_date TEXT NOT NULL, activity_type TEXT NOT NULL,
          pay_basis TEXT NOT NULL, quantity_milli INTEGER NOT NULL CHECK(quantity_milli > 0),
          rate_paise INTEGER NOT NULL CHECK(rate_paise >= 0), charge_paise INTEGER NOT NULL CHECK(charge_paise >= 0),
          cost_allocated INTEGER NOT NULL DEFAULT 0 CHECK(cost_allocated IN (0,1)),
          invoice_ref TEXT NOT NULL DEFAULT '', invoice_doc TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
          recorded_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_labor_work_date ON labor_work(work_date,created_at);
        CREATE INDEX IF NOT EXISTS idx_labor_work_contractor ON labor_work(contractor_id,work_date);
        CREATE TABLE IF NOT EXISTS maintenance_records (
          id TEXT PRIMARY KEY, maintenance_code TEXT NOT NULL UNIQUE,
          machine_id TEXT NOT NULL REFERENCES machines(id), work_type TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('planned','completed')),
          work_date TEXT NOT NULL, next_due_date TEXT NOT NULL DEFAULT '', downtime_hours_milli INTEGER NOT NULL DEFAULT 0 CHECK(downtime_hours_milli >= 0),
          cost_paise INTEGER NOT NULL DEFAULT 0 CHECK(cost_paise >= 0), invoice_ref TEXT NOT NULL DEFAULT '',
          invoice_doc TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
          recorded_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_maintenance_machine_date ON maintenance_records(machine_id,work_date DESC);
        """)
        # Additive migration so data created by an earlier local MVP build remains readable.
        receipt_columns = {r[1] for r in db.execute("PRAGMA table_info(receipts)")}
        if "quality_note" not in receipt_columns:
            db.execute("ALTER TABLE receipts ADD COLUMN quality_note TEXT NOT NULL DEFAULT ''")
        labor_work_columns = {r[1] for r in db.execute("PRAGMA table_info(labor_work)")}
        if "cost_allocated" not in labor_work_columns:
            db.execute("ALTER TABLE labor_work ADD COLUMN cost_allocated INTEGER NOT NULL DEFAULT 0 CHECK(cost_allocated IN (0,1))")
        sales_columns = {r[1] for r in db.execute("PRAGMA table_info(sales)")}
        if "customer_id" not in sales_columns:
            db.execute("ALTER TABLE sales ADD COLUMN customer_id TEXT REFERENCES customers(id)")
        production_columns={r[1] for r in db.execute("PRAGMA table_info(production_runs)")}
        production_migrations={
            "machine_id":"TEXT REFERENCES machines(id)", "machine_label":"TEXT NOT NULL DEFAULT ''",
            "machine_hours_milli":"INTEGER NOT NULL DEFAULT 0 CHECK(machine_hours_milli >= 0)",
            "machine_cost_per_hour_paise":"INTEGER NOT NULL DEFAULT 0 CHECK(machine_cost_per_hour_paise >= 0)",
            "machine_cost_paise":"INTEGER NOT NULL DEFAULT 0 CHECK(machine_cost_paise >= 0)",
            "energy_kwh_milli":"INTEGER NOT NULL DEFAULT 0 CHECK(energy_kwh_milli >= 0)",
            "electricity_rate_paise_per_kwh":"INTEGER NOT NULL DEFAULT 0 CHECK(electricity_rate_paise_per_kwh >= 0)"
        }
        for column,definition in production_migrations.items():
            if column not in production_columns: db.execute(f"ALTER TABLE production_runs ADD COLUMN {column} {definition}")
        # Convert historical free-text sale party names into reusable customer records.
        legacy_names = db.execute("SELECT DISTINCT TRIM(customer_name) name FROM sales WHERE customer_id IS NULL AND TRIM(customer_name)<>'' ORDER BY name COLLATE NOCASE").fetchall()
        for row in legacy_names:
            name = row["name"]
            customer = db.execute("SELECT id FROM customers WHERE name=? COLLATE NOCASE ORDER BY created_at LIMIT 1", (name,)).fetchone()
            if not customer:
                identity, created = str(uuid.uuid4()), now_iso()
                db.execute("INSERT INTO customers(id,customer_code,name,created_at,updated_at) VALUES(?,?,?,?,?)", (identity,new_code("CUS"),name,created,created))
                customer = {"id": identity}
            db.execute("UPDATE sales SET customer_id=? WHERE customer_id IS NULL AND customer_name=? COLLATE NOCASE", (customer["id"],name))
        db.execute("CREATE INDEX IF NOT EXISTS idx_sales_customer ON sales(customer_id,occurred_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_gstin_unique ON customers(gstin) WHERE gstin<>''")
        count = db.execute("SELECT COUNT(*) FROM grades").fetchone()[0]
        if count == 0:
            starter = [
                ("PET-CLR-BTL", "PET Clear Bottle", "PET", "Bottle", "Clear"),
                ("PET-BLU-BTL", "PET Blue Bottle", "PET", "Bottle", "Blue"),
                ("PET-GRN-BTL", "PET Green Bottle", "PET", "Bottle", "Green"),
                ("PET-MIX-BTL", "PET Mixed Bottle", "PET", "Bottle", "Mixed"),
                ("HDPE-MIX-RIG", "HDPE Mixed Rigid", "HDPE", "Rigid", "Mixed"),
                ("PP-MIX-RIG", "PP Mixed Rigid", "PP", "Rigid", "Mixed"),
            ]
            for code, name, polymer, form, color in starter:
                db.execute("INSERT INTO grades VALUES(?,?,?,?,?,?,1,?)", (str(uuid.uuid4()), code, name, polymer, form, color, now_iso()))


def as_int_kg(value, label, *, allow_zero=False):
    try:
        d = Decimal(str(value).strip())
        if not d.is_finite() or d < 0 or (not allow_zero and d <= 0):
            raise ValueError(f"{label} must be {'zero or more' if allow_zero else 'greater than zero'} kg")
        return int((d * 1000).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, AttributeError):
        raise ValueError(f"Enter a valid {label} in kg")


def as_paise(value, label, *, allow_zero=False):
    try:
        d = Decimal(str(value).strip())
        if not d.is_finite() or d < 0 or (not allow_zero and d <= 0):
            raise ValueError(f"{label} must be {'zero or more' if allow_zero else 'greater than zero'}")
        return int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, AttributeError):
        raise ValueError(f"Enter a valid {label}")


def kg(g):
    return round(g / 1000, 3)


def rupees(paise):
    return round(paise / 100, 2)


LABOR_BASES = {"input_kg", "output_kg", "output_ton", "shift", "day", "bale", "fixed_job", "invoice"}
LABOR_ACTIVITIES = {"grading", "grinding", "baling", "sorting", "handling", "other"}


def labor_unit(basis):
    return {"input_kg":"input kg", "output_kg":"finished kg", "output_ton":"finished tonne", "shift":"shift", "day":"day", "bale":"bale", "fixed_job":"job", "invoice":"invoice"}.get(basis, "unit")


def as_milli(value, label, *, allow_one=False):
    try:
        d=Decimal(str(value).strip())
        if not d.is_finite() or d<=0: raise ValueError
        result=int((d*1000).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        if allow_one and result!=1000: raise ValueError
        return result
    except (InvalidOperation,AttributeError,ValueError):
        if allow_one: raise ValueError(f"{label} must be 1 for a fixed job or invoice")
        raise ValueError(f"Enter a valid {label} greater than zero")


def as_milli_nonnegative(value,label):
    if str(value if value is not None else "").strip()=="": return 0
    try:
        d=Decimal(str(value).strip())
        if not d.is_finite() or d<0 or d>Decimal("10000000"): raise ValueError
        return int((d*1000).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
    except (InvalidOperation,AttributeError,ValueError):
        raise ValueError(f"Enter a valid {label} of zero or more")


def valid_date(value, label):
    value=str(value or "").strip()
    try:
        if datetime.strptime(value,"%Y-%m-%d").strftime("%Y-%m-%d")!=value: raise ValueError
    except (ValueError,TypeError): raise ValueError(f"Choose a valid {label}")
    return value


def new_code(prefix):
    stamp = datetime.now().strftime("%y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:4].upper()}"


def audit(db, event, kind, identity, detail):
    db.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), event, kind, identity, json.dumps(detail, sort_keys=True), now_iso()))


def as_timestamp(value, label):
    try:
        raw = str(value or "").strip()
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else datetime.now(timezone.utc)
        if stamp.tzinfo is None:
            raise ValueError
        return stamp.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"Enter a valid {label} with a timezone")


def safe_document_path(value):
    path = str(value or "").strip()
    if not path:
        return ""
    if not re.fullmatch(r"/documents/[a-f0-9-]+\.(jpg|png|pdf|webp)", path):
        raise ValueError("Select a valid uploaded document")
    file = (UPLOAD_DIR / path.rsplit("/", 1)[-1]).resolve()
    if file.parent != UPLOAD_DIR.resolve() or not file.is_file():
        raise ValueError("The uploaded document could not be found")
    return path


def current_stock(db, lot_id):
    return db.execute("SELECT COALESCE(SUM(delta_g),0) FROM stock_events WHERE lot_id=?", (lot_id,)).fetchone()[0]


def lot_rows(db):
    return db.execute("""
      SELECT l.id,l.lot_code,l.source_type,l.source_id,l.created_at,l.initial_qty_g,l.cost_per_kg_paise,l.status,
             g.code grade_code,g.name grade_name,g.polymer,g.form,g.color,
             COALESCE(SUM(e.delta_g),0) balance_g
      FROM lots l JOIN grades g ON g.id=l.grade_id LEFT JOIN stock_events e ON e.lot_id=l.id
      GROUP BY l.id ORDER BY l.created_at DESC
    """).fetchall()


def json_lot(row):
    return {"id":row["id"],"code":row["lot_code"],"source_type":row["source_type"],"source_id":row["source_id"],"created_at":row["created_at"],"initial_kg":kg(row["initial_qty_g"]),"balance_kg":kg(row["balance_g"]),"cost_per_kg":rupees(row["cost_per_kg_paise"]),"grade_code":row["grade_code"],"grade_name":row["grade_name"],"polymer":row["polymer"],"form":row["form"],"color":row["color"],"status":row["status"]}


def bootstrap():
    with conn() as db:
        lots = [json_lot(r) for r in lot_rows(db)]
        suppliers = [dict(r) for r in db.execute("SELECT id,name,phone,notes,created_at FROM suppliers ORDER BY name")]
        customers = [dict(r) for r in db.execute("SELECT id,customer_code,name,contact_name,phone,email,gstin,billing_address,active,created_at FROM customers ORDER BY active DESC,name")]
        employees = [{"id":r["id"],"employee_code":r["employee_code"],"name":r["name"],"job_title":r["job_title"],"phone":r["phone"],"hourly_rate_per_hour":rupees(r["hourly_rate_paise"]),"active":bool(r["active"]),"created_at":r["created_at"]} for r in db.execute("SELECT * FROM employees ORDER BY active DESC,name")]
        contractors = [{"id":r["id"],"contractor_code":r["contractor_code"],"name":r["name"],"contact_name":r["contact_name"],"phone":r["phone"],"active":bool(r["active"]),"notes":r["notes"],"created_at":r["created_at"]} for r in db.execute("SELECT * FROM contractors ORDER BY active DESC,name")]
        machines=[]
        for r in db.execute("SELECT * FROM machines ORDER BY active DESC,process_area,name"):
            machines.append({"id":r["id"],"machine_code":r["machine_code"],"name":r["name"],"process_area":r["process_area"],"rated_power_kw":round(r["rated_power_kw_milli"]/1000,3),"machine_cost_per_hour":rupees(r["machine_cost_per_hour_paise"]),"electricity_rate_per_kwh":rupees(r["electricity_rate_paise_per_kwh"]),"active":bool(r["active"]),"notes":r["notes"],"created_at":r["created_at"]})
        maintenance_records=[]
        for r in db.execute("SELECT m.*,a.machine_code,a.name machine_name FROM maintenance_records m JOIN machines a ON a.id=m.machine_id ORDER BY m.work_date DESC,m.created_at DESC LIMIT 300"):
            maintenance_records.append({"id":r["id"],"code":r["maintenance_code"],"machine_id":r["machine_id"],"machine_code":r["machine_code"],"machine_name":r["machine_name"],"work_type":r["work_type"],"status":r["status"],"work_date":r["work_date"],"next_due_date":r["next_due_date"],"downtime_hours":round(r["downtime_hours_milli"]/1000,3),"cost":rupees(r["cost_paise"]),"invoice_ref":r["invoice_ref"],"invoice_doc":r["invoice_doc"],"notes":r["notes"],"created_at":r["created_at"]})
        contracts = []
        for r in db.execute("SELECT c.*,p.name contractor_name,p.contractor_code FROM labor_contracts c JOIN contractors p ON p.id=c.contractor_id ORDER BY c.active DESC,c.valid_from DESC"):
            contracts.append({"id":r["id"],"contract_code":r["contract_code"],"contractor_id":r["contractor_id"],"contractor_name":r["contractor_name"],"contractor_code":r["contractor_code"],"activity_type":r["activity_type"],"pay_basis":r["pay_basis"],"unit_label":labor_unit(r["pay_basis"]),"rate_per_unit":rupees(r["rate_paise"]),"valid_from":r["valid_from"],"valid_to":r["valid_to"],"active":bool(r["active"]),"notes":r["notes"]})
        labor_work = []
        for r in db.execute("SELECT w.*,p.name contractor_name,p.contractor_code,c.contract_code,pr.run_code FROM labor_work w JOIN contractors p ON p.id=w.contractor_id JOIN labor_contracts c ON c.id=w.contract_id LEFT JOIN production_runs pr ON pr.id=w.production_run_id ORDER BY w.work_date DESC,w.created_at DESC LIMIT 300"):
            labor_work.append({"id":r["id"],"code":r["work_code"],"contractor_id":r["contractor_id"],"contractor_name":r["contractor_name"],"contractor_code":r["contractor_code"],"contract_id":r["contract_id"],"contract_code":r["contract_code"],"production_run_id":r["production_run_id"],"production_run_code":r["run_code"],"work_date":r["work_date"],"activity_type":r["activity_type"],"pay_basis":r["pay_basis"],"unit_label":labor_unit(r["pay_basis"]),"quantity":r["quantity_milli"]/1000,"rate_per_unit":rupees(r["rate_paise"]),"charge":rupees(r["charge_paise"]),"cost_allocated":bool(r["cost_allocated"]),"invoice_ref":r["invoice_ref"],"invoice_doc":r["invoice_doc"],"invoice_status":"documented" if r["invoice_doc"] else "pending","note":r["note"],"created_at":r["created_at"]})
        grades = [dict(r) for r in db.execute("SELECT id,code,name,polymer,form,color,active FROM grades WHERE active=1 ORDER BY polymer,code")]
        receipts = []
        for r in db.execute("SELECT r.*,s.name supplier,g.name grade,l.lot_code FROM receipts r JOIN suppliers s ON s.id=r.supplier_id JOIN grades g ON g.id=r.grade_id JOIN lots l ON l.id=r.lot_id ORDER BY r.created_at DESC LIMIT 100"):
            receipts.append({"id":r["id"],"code":r["receipt_code"],"supplier":r["supplier"],"grade":r["grade"],"lot_code":r["lot_code"],"vehicle_no":r["vehicle_no"],"accepted_kg":kg(r["accepted_g"]),"gross_kg":kg(r["gross_g"]),"tare_kg":kg(r["tare_g"]),"rate_per_kg":rupees(r["rate_paise"]),"invoice_total":rupees(r["invoice_total_paise"]),"invoice_status":r["invoice_status"],"invoice_doc":r["invoice_doc"],"occurred_at":r["occurred_at"],"scale_ticket":r["scale_ticket"],"quality_note":r["quality_note"]})
        runs=[]
        for r in db.execute("SELECT p.*,i.lot_code input_code,o.lot_code output_code,ig.name input_grade,og.name output_grade FROM production_runs p JOIN lots i ON i.id=p.input_lot_id JOIN lots o ON o.id=p.output_lot_id JOIN grades ig ON ig.id=i.grade_id JOIN grades og ON og.id=p.output_grade_id ORDER BY p.created_at DESC LIMIT 100"):
            runs.append({"id":r["id"],"code":r["run_code"],"input_lot":r["input_code"],"output_lot":r["output_code"],"input_grade":r["input_grade"],"output_grade":r["output_grade"],"input_kg":kg(r["input_g"]),"output_kg":kg(r["output_g"]),"loss_kg":kg(r["loss_g"]),"yield_pct":round(100*r["output_g"]/r["input_g"],1),"labor_cost":rupees(r["labor_paise"]),"energy_cost":rupees(r["energy_paise"]),"energy_kwh":round(r["energy_kwh_milli"]/1000,3),"electricity_rate_per_kwh":rupees(r["electricity_rate_paise_per_kwh"]),"machine_id":r["machine_id"],"machine_label":r["machine_label"],"machine_hours":round(r["machine_hours_milli"]/1000,3),"machine_cost_per_hour":rupees(r["machine_cost_per_hour_paise"]),"machine_cost":rupees(r["machine_cost_paise"]),"total_cost":rupees(r["total_cost_paise"]),"occurred_at":r["occurred_at"]})
        sales=[]
        for r in db.execute("SELECT s.*,l.lot_code,g.name grade,c.name registered_customer FROM sales s JOIN lots l ON l.id=s.lot_id JOIN grades g ON g.id=l.grade_id LEFT JOIN customers c ON c.id=s.customer_id ORDER BY s.created_at DESC LIMIT 100"):
            sales.append({"id":r["id"],"code":r["sale_code"],"customer_id":r["customer_id"],"customer":r["registered_customer"] or r["customer_name"],"lot_code":r["lot_code"],"grade":r["grade"],"quantity_kg":kg(r["quantity_g"]),"rate_per_kg":rupees(r["rate_paise"]),"invoice_total":rupees(r["invoice_total_paise"]),"cogs":rupees(r["cogs_paise"]),"contribution":rupees(r["invoice_total_paise"]-r["cogs_paise"]),"invoice_doc":r["invoice_doc"],"vehicle_no":r["vehicle_no"],"occurred_at":r["occurred_at"]})
        time_entries=[]
        for r in db.execute("SELECT t.*,e.employee_code,e.name employee_name,e.job_title FROM time_entries t JOIN employees e ON e.id=t.employee_id ORDER BY t.work_date DESC,t.clock_in_at DESC LIMIT 200"):
            time_entries.append({"id":r["id"],"employee_id":r["employee_id"],"employee_code":r["employee_code"],"employee_name":r["employee_name"],"job_title":r["job_title"],"work_date":r["work_date"],"shift_label":r["shift_label"],"clock_in_at":r["clock_in_at"],"clock_out_at":r["clock_out_at"],"break_minutes":r["break_minutes"],"minutes_worked":r["minutes_worked"],"hours_worked":round(r["minutes_worked"]/60,2),"hourly_rate":rupees(r["hourly_rate_paise"]),"labor_cost":rupees(r["labor_cost_paise"]),"note":r["note"]})
        total_stock=sum(x["balance_kg"] for x in lots)
        purchase_total=db.execute("SELECT COALESCE(SUM(invoice_total_paise),0) FROM receipts").fetchone()[0]
        sales_total=db.execute("SELECT COALESCE(SUM(invoice_total_paise),0) FROM sales").fetchone()[0]
        contribution=db.execute("SELECT COALESCE(SUM(invoice_total_paise-cogs_paise),0) FROM sales").fetchone()[0]
        today=datetime.now().astimezone().date().isoformat()
        day=db.execute("SELECT COUNT(*) shifts,COALESCE(SUM(minutes_worked),0) minutes,COALESCE(SUM(labor_cost_paise),0) labor_cost FROM time_entries WHERE work_date=?",(today,)).fetchone()
        labor_day=db.execute("SELECT COUNT(*) work_count,COALESCE(SUM(charge_paise),0) cost FROM labor_work WHERE work_date=?",(today,)).fetchone()
        labor_month=db.execute("SELECT COALESCE(SUM(charge_paise),0) cost FROM labor_work WHERE substr(work_date,1,7)=?",(today[:7],)).fetchone()[0]
        result={"suppliers":suppliers,"customers":customers,"employees":employees,"time_entries":time_entries,"contractors":contractors,"labor_contracts":contracts,"labor_work":labor_work,"machines":machines,"maintenance_records":maintenance_records,"grades":grades,"lots":lots,"receipts":receipts,"runs":runs,"sales":sales,
          "summary":{"stock_kg":round(total_stock,3),"purchase_total":rupees(purchase_total),"sales_total":rupees(sales_total),"sales_contribution":rupees(contribution),"supplier_count":len(suppliers),"customer_count":sum(1 for c in customers if c["active"]),"lot_count":len(lots),"employee_count":sum(1 for e in employees if e["active"]),"shifts_today":day["shifts"],"labor_minutes_today":day["minutes"],"labor_cost_today":rupees(day["labor_cost"]),"contractor_count":sum(1 for p in contractors if p["active"]),"active_contract_count":sum(1 for c in contracts if c["active"]),"contract_work_today":labor_day["work_count"],"contract_labor_cost_today":rupees(labor_day["cost"]),"contract_labor_cost_month":rupees(labor_month),"contract_invoice_pending_count":sum(1 for w in labor_work if w["invoice_status"]=="pending")}}
        return result


class ApiError(Exception):
    def __init__(self, message, status=400): self.message,self.status=message,status


def user_payload(row):
    return {"id":row["id"],"email":row["email"],"display_name":row["display_name"],"role":row["role"]}


def normalize_email(value):
    email=str(value or "").strip().lower()
    if len(email)>254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):
        raise ValueError("Enter a valid email address")
    return email


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,PASSWORD_ITERATIONS).hex()


def validate_new_password(value):
    password=str(value or "")
    if len(password)<12: raise ValueError("Use a password with at least 12 characters")
    if len(password)>128: raise ValueError("Password must be 128 characters or fewer")
    return password


def insert_session(db,user_id):
    raw_token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32); created=now_iso()
    expires=(datetime.now(timezone.utc).timestamp()+SESSION_MAX_AGE)
    expires_at=datetime.fromtimestamp(expires,tz=timezone.utc).isoformat(timespec="seconds")
    token_hash=hashlib.sha256(raw_token.encode()).hexdigest()
    db.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",(token_hash,user_id,csrf,expires_at,created))
    return raw_token,csrf


def create_first_owner(data):
    email=normalize_email(data.get("email")); name=str(data.get("display_name","")).strip()
    if not name or len(name)>120: raise ValueError("Enter your name (up to 120 characters)")
    password=validate_new_password(data.get("password")); salt=secrets.token_bytes(16); digest=password_digest(password,salt)
    identity=str(uuid.uuid4()); created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone(): raise ApiError("Workspace setup has already been completed",409)
        db.execute("INSERT INTO users(id,email,display_name,role,password_salt,password_hash,active,created_at,updated_at) VALUES(?,?,?,'owner',?,?,1,?,?)",(identity,email,name,salt.hex(),digest,created,created))
        raw_token,csrf=insert_session(db,identity)
        audit(db,"user.owner_setup","user",identity,{"email":email})
    return {"token":raw_token,"csrf_token":csrf,"user":{"id":identity,"email":email,"display_name":name,"role":"owner"}}


def login_user(data,remote_ip="local"):
    try: email=normalize_email(data.get("email"))
    except ValueError: email="invalid"
    password=str(data.get("password", ""))
    if len(password)>128: password=password[:128]
    attempt_key=hashlib.sha256((email+"|"+remote_ip).encode()).hexdigest()
    now=datetime.now(timezone.utc); now_text=now.isoformat(timespec="seconds")
    with conn() as db:
        attempt=db.execute("SELECT failure_count,window_started FROM login_attempts WHERE attempt_key=?",(attempt_key,)).fetchone()
        count=0; window=now_text
        if attempt:
            window=attempt["window_started"]
            try: age=(now-datetime.fromisoformat(window)).total_seconds()
            except ValueError: age=901
            if age<900: count=attempt["failure_count"]
            else: window=now_text
        if count>=8: raise ApiError("Too many sign-in attempts. Try again in 15 minutes.",429)
        user=db.execute("SELECT * FROM users WHERE email=? AND active=1",(email,)).fetchone()
        if user:
            salt=bytes.fromhex(user["password_salt"]); expected=user["password_hash"]
        else:
            salt=hashlib.sha256(b"orbitplus-invalid-user-salt").digest()[:16]; expected="0"*64
        actual=password_digest(password,salt)
        if not user or not hmac.compare_digest(actual,expected):
            db.execute("INSERT INTO login_attempts(attempt_key,failure_count,window_started) VALUES(?,?,?) ON CONFLICT(attempt_key) DO UPDATE SET failure_count=excluded.failure_count,window_started=excluded.window_started",(attempt_key,count+1,window))
            db.commit()
            raise ApiError("Email or password is incorrect",401)
        db.execute("DELETE FROM login_attempts WHERE attempt_key=?",(attempt_key,))
        raw_token,csrf=insert_session(db,user["id"])
        audit(db,"user.login","user",user["id"],{"email":user["email"]})
        return {"token":raw_token,"csrf_token":csrf,"user":user_payload(user)}


def session_for_token(raw_token):
    if not raw_token: return None
    token_hash=hashlib.sha256(raw_token.encode()).hexdigest()
    with conn() as db:
        row=db.execute("SELECT s.token_hash,s.csrf_token,s.expires_at,u.id,u.email,u.display_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1",(token_hash,)).fetchone()
        if not row: return None
        try: valid=datetime.fromisoformat(row["expires_at"])>datetime.now(timezone.utc)
        except ValueError: valid=False
        if not valid:
            db.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash,)); return None
        return {"token_hash":row["token_hash"],"csrf_token":row["csrf_token"],"expires_at":row["expires_at"],"user":{"id":row["id"],"email":row["email"],"display_name":row["display_name"],"role":row["role"]}}


def users_exist():
    with conn() as db: return bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone())


def list_users():
    with conn() as db:
        return [{"id":r["id"],"email":r["email"],"display_name":r["display_name"],"role":r["role"],"active":bool(r["active"]),"created_at":r["created_at"]} for r in db.execute("SELECT id,email,display_name,role,active,created_at FROM users ORDER BY created_at")]


def create_staff_user(data,actor_id):
    email=normalize_email(data.get("email")); name=str(data.get("display_name","")).strip(); role=str(data.get("role", ""))
    if not name or len(name)>120: raise ValueError("Enter a staff member name (up to 120 characters)")
    if role not in ALLOWED_ROLES-{"owner"}: raise ValueError("Choose operations, finance or viewer access")
    password=validate_new_password(data.get("password")); salt=secrets.token_bytes(16); digest=password_digest(password,salt)
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO users(id,email,display_name,role,password_salt,password_hash,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",(identity,email,name,role,salt.hex(),digest,created,created))
            audit(db,"user.created","user",identity,{"email":email,"role":role,"created_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("An account with that email already exists")
    return {"id":identity,"email":email,"display_name":name,"role":role,"active":True,"created_at":created}


def create_employee(data,actor_id):
    code=str(data.get("employee_code","")).strip().upper()
    name=str(data.get("name","")).strip()
    title=str(data.get("job_title","")).strip()
    phone=str(data.get("phone","")).strip()
    rate=as_paise(data.get("hourly_rate_per_hour",0),"hourly labour cost rate",allow_zero=True)
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}",code): raise ValueError("Employee code must use 1–32 letters, numbers, dot, underscore or hyphen")
    if not name or len(name)>120: raise ValueError("Enter an employee name (up to 120 characters)")
    if not title or len(title)>60: raise ValueError("Enter a job role (up to 60 characters)")
    if len(phone)>40: raise ValueError("Phone number is too long")
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO employees(id,employee_code,name,job_title,phone,hourly_rate_paise,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",(identity,code,name,title,phone,rate,created,created))
            audit(db,"employee.created","employee",identity,{"employee_code":code,"job_title":title,"created_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("That employee code already exists")
    return {"id":identity,"employee_code":code,"name":name,"job_title":title,"phone":phone,"hourly_rate_per_hour":rupees(rate),"active":True,"created_at":created}


def create_time_entry(data,actor_id):
    employee_id=str(data.get("employee_id",""))
    work_date=str(data.get("work_date","")).strip()
    try:
        if datetime.strptime(work_date,"%Y-%m-%d").strftime("%Y-%m-%d")!=work_date: raise ValueError
    except (ValueError,TypeError): raise ValueError("Choose a valid shift date")
    shift=str(data.get("shift_label","")).strip() or "Day"
    if len(shift)>40: raise ValueError("Shift name must be 40 characters or fewer")
    clock_in=as_timestamp(data.get("clock_in_at"),"clock-in time")
    clock_out=as_timestamp(data.get("clock_out_at"),"clock-out time")
    start=datetime.fromisoformat(clock_in); finish=datetime.fromisoformat(clock_out)
    duration_seconds=(finish-start).total_seconds()
    if duration_seconds<=0: raise ValueError("Clock-out must be later than clock-in")
    if work_date!=start.astimezone().date().isoformat(): raise ValueError("Shift date must match the local clock-in date")
    if finish>datetime.now(timezone.utc)+timedelta(minutes=5): raise ValueError("Clock-out time must not be in the future")
    if duration_seconds>18*60*60: raise ValueError("A shift cannot exceed 18 hours")
    minutes=int((Decimal(str(duration_seconds))/Decimal(60)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
    try: break_minutes=int(str(data.get("break_minutes",0)))
    except (ValueError,TypeError): raise ValueError("Break time must be a whole number of minutes")
    if break_minutes<0 or break_minutes>=minutes: raise ValueError("Break time must be non-negative and shorter than the shift")
    note=str(data.get("note","")).strip()[:300]
    identity=str(uuid.uuid4()); created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        employee=db.execute("SELECT id,employee_code,name,job_title,hourly_rate_paise FROM employees WHERE id=? AND active=1",(employee_id,)).fetchone()
        if not employee: raise ValueError("Select an active team member")
        if db.execute("SELECT 1 FROM time_entries WHERE employee_id=? AND work_date=? AND shift_label=?",(employee_id,work_date,shift)).fetchone():
            raise ValueError("This team member already has a time entry for that date and shift")
        overlap=db.execute("SELECT 1 FROM time_entries WHERE employee_id=? AND clock_in_at<? AND clock_out_at>? LIMIT 1",(employee_id,clock_out,clock_in)).fetchone()
        if overlap: raise ValueError("This time entry overlaps another recorded shift")
        worked=minutes-break_minutes
        cost=int((Decimal(employee["hourly_rate_paise"])*Decimal(worked)/Decimal(60)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        db.execute("INSERT INTO time_entries(id,employee_id,work_date,shift_label,clock_in_at,clock_out_at,break_minutes,minutes_worked,hourly_rate_paise,labor_cost_paise,note,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(identity,employee_id,work_date,shift,clock_in,clock_out,break_minutes,worked,employee["hourly_rate_paise"],cost,note,actor_id,created))
        audit(db,"time_entry.created","time_entry",identity,{"employee_code":employee["employee_code"],"work_date":work_date,"shift":shift,"minutes_worked":worked,"recorded_by":actor_id})
    return {"id":identity,"employee_id":employee_id,"employee_code":employee["employee_code"],"employee_name":employee["name"],"job_title":employee["job_title"],"work_date":work_date,"shift_label":shift,"clock_in_at":clock_in,"clock_out_at":clock_out,"break_minutes":break_minutes,"minutes_worked":worked,"hours_worked":round(worked/60,2),"hourly_rate":rupees(employee["hourly_rate_paise"]),"labor_cost":rupees(cost),"note":note}


def create_contractor(data,actor_id):
    code=str(data.get("contractor_code","")).strip().upper()
    name=str(data.get("name","")).strip()
    contact=str(data.get("contact_name","")).strip()
    phone=str(data.get("phone","")).strip()
    notes=str(data.get("notes","")).strip()[:400]
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}",code): raise ValueError("Contractor code must use 1–32 letters, numbers, dot, underscore or hyphen")
    if not name or len(name)>120: raise ValueError("Enter a contractor or business name (up to 120 characters)")
    if len(contact)>120 or len(phone)>40: raise ValueError("Contractor contact details are too long")
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO contractors(id,contractor_code,name,contact_name,phone,active,notes,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?,?)",(identity,code,name,contact,phone,notes,created,created))
            audit(db,"contractor.created","contractor",identity,{"contractor_code":code,"created_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("That contractor code already exists")
    return {"id":identity,"contractor_code":code,"name":name,"contact_name":contact,"phone":phone,"active":True,"notes":notes,"created_at":created}


def create_labor_contract(data,actor_id):
    contractor_id=str(data.get("contractor_id",""))
    code=str(data.get("contract_code","")).strip().upper() or new_code("CTR")
    activity=str(data.get("activity_type","")).strip().lower()
    basis=str(data.get("pay_basis","")).strip().lower()
    rate=as_paise(data.get("rate_per_unit"),"contract rate",allow_zero=True)
    start=valid_date(data.get("valid_from"),"contract start date")
    end=str(data.get("valid_to","")).strip()
    if end: end=valid_date(end,"contract end date")
    if end and end<start: raise ValueError("Contract end date cannot be before its start date")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}",code): raise ValueError("Contract code must use 1–32 letters, numbers, dot, underscore or hyphen")
    if activity not in LABOR_ACTIVITIES: raise ValueError("Choose grading, grinding, baling, sorting, handling or other work")
    if basis not in LABOR_BASES: raise ValueError("Choose a supported contract payment basis")
    notes=str(data.get("notes","")).strip()[:400]
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            contractor=db.execute("SELECT id FROM contractors WHERE id=? AND active=1",(contractor_id,)).fetchone()
            if not contractor: raise ValueError("Select an active contractor")
            db.execute("INSERT INTO labor_contracts(id,contract_code,contractor_id,activity_type,pay_basis,rate_paise,valid_from,valid_to,active,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?,?,?)",(identity,code,contractor_id,activity,basis,rate,start,end,notes,created,created))
            audit(db,"labor_contract.created","labor_contract",identity,{"contract_code":code,"activity_type":activity,"pay_basis":basis,"rate_paise":rate,"created_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("That contract code already exists")
    return {"id":identity,"contract_code":code,"contractor_id":contractor_id,"activity_type":activity,"pay_basis":basis,"unit_label":labor_unit(basis),"rate_per_unit":rupees(rate),"valid_from":start,"valid_to":end,"active":True,"notes":notes}


def create_labor_work(data,actor_id,allow_cost_allocation=True):
    contract_id=str(data.get("contract_id",""))
    work_date=valid_date(data.get("work_date"),"work date")
    today=datetime.now().astimezone().date().isoformat()
    if work_date>today: raise ValueError("Contract work date cannot be in the future")
    quantity_value=str(data.get("quantity", "")).strip()
    quantity_milli=as_milli(quantity_value,"work quantity") if quantity_value else None
    run_id=str(data.get("production_run_id","")).strip() or None
    allocate_cost=str(data.get("allocate_cost","")).strip().lower() in {"1","true","yes","on"}
    if allocate_cost and not allow_cost_allocation: raise ValueError("Only owner or finance users can allocate contractor charges to production cost")
    if allocate_cost and not run_id: raise ValueError("Select a production run before allocating this charge")
    invoice_ref=str(data.get("invoice_ref","")).strip()
    if len(invoice_ref)>80: raise ValueError("Invoice reference must be 80 characters or fewer")
    doc=safe_document_path(data.get("invoice_doc",""))
    note=str(data.get("note","")).strip()[:400]
    identity=str(uuid.uuid4()); code=new_code("LAB"); created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        contract=db.execute("SELECT c.*,p.name contractor_name,p.contractor_code FROM labor_contracts c JOIN contractors p ON p.id=c.contractor_id WHERE c.id=? AND c.active=1 AND p.active=1",(contract_id,)).fetchone()
        if not contract: raise ValueError("Select an active contractor contract")
        if work_date<contract["valid_from"] or (contract["valid_to"] and work_date>contract["valid_to"]): raise ValueError("Work date is outside this contract’s effective dates")
        basis=contract["pay_basis"]
        run=db.execute("SELECT p.id,p.run_code,p.output_g,p.output_lot_id,p.labor_paise,p.material_cost_paise,p.energy_paise,p.machine_cost_paise FROM production_runs p WHERE p.id=?",(run_id,)).fetchone() if run_id else None
        if run_id and not run: raise ValueError("Select a valid production run")
        if basis in {"output_kg","output_ton"}:
            if not run: raise ValueError("Link a production run to bill against finished output weight")
            existing=db.execute("SELECT COALESCE(SUM(CASE WHEN pay_basis='output_ton' THEN quantity_milli*1000 ELSE quantity_milli END),0) FROM labor_work WHERE production_run_id=? AND activity_type=? AND pay_basis IN ('output_kg','output_ton')",(run_id,contract["activity_type"])).fetchone()[0]
            remaining_grams=run["output_g"]-existing
            if remaining_grams<=0: raise ValueError("The finished output weight for this activity has already been fully billed")
            if quantity_milli is None:
                quantity_milli=remaining_grams if basis=="output_kg" else remaining_grams//1000
                if quantity_milli<=0: raise ValueError("The remaining output is less than the 0.001 tonne billing increment")
            grams=quantity_milli if basis=="output_kg" else quantity_milli*1000
            if existing+grams>run["output_g"]: raise ValueError("Contract quantity cannot exceed the linked run’s remaining finished output weight for this activity")
        elif quantity_milli is None:
            raise ValueError("Enter the billable quantity for this contract")
        if basis in {"shift","day","bale"} and quantity_milli%1000: raise ValueError(f"{labor_unit(basis).title()} quantity must be a whole number")
        if basis in {"fixed_job","invoice"} and quantity_milli!=1000: raise ValueError(f"Quantity must be 1 for a {labor_unit(basis)} contract")
        if allocate_cost:
            if db.execute("SELECT 1 FROM sales WHERE lot_id=? LIMIT 1",(run["output_lot_id"],)).fetchone():
                raise ValueError("This run already has a dispatch; a controlled cost adjustment is needed before changing its allocated labour")
            if db.execute("SELECT 1 FROM stock_events WHERE lot_id=? AND event_type='production_consumption' LIMIT 1",(run["output_lot_id"],)).fetchone():
                raise ValueError("This output lot has been used in another production run; a controlled cost adjustment is needed")
        charge=int((Decimal(quantity_milli)*Decimal(contract["rate_paise"])/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        db.execute("INSERT INTO labor_work(id,work_code,contractor_id,contract_id,production_run_id,work_date,activity_type,pay_basis,quantity_milli,rate_paise,charge_paise,cost_allocated,invoice_ref,invoice_doc,note,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(identity,code,contract["contractor_id"],contract_id,run_id,work_date,contract["activity_type"],basis,quantity_milli,contract["rate_paise"],charge,int(allocate_cost),invoice_ref,doc,note,actor_id,created))
        if allocate_cost:
            total_labor=run["labor_paise"]+charge
            total_cost=run["material_cost_paise"]+total_labor+run["energy_paise"]+run["machine_cost_paise"]
            unit_cost=int((Decimal(total_cost)*Decimal(1000)/Decimal(run["output_g"])).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
            db.execute("UPDATE production_runs SET labor_paise=?,total_cost_paise=? WHERE id=?",(total_labor,total_cost,run_id))
            db.execute("UPDATE lots SET cost_per_kg_paise=? WHERE id=?",(unit_cost,run["output_lot_id"]))
            audit(db,"production.contract_labor_allocated","production_run",run_id,{"work_code":code,"charge_paise":charge,"labor_total_paise":total_labor,"production_cost_paise":total_cost,"allocated_by":actor_id})
        audit(db,"labor_work.recorded","labor_work",identity,{"work_code":code,"contract_code":contract["contract_code"],"work_date":work_date,"quantity_milli":quantity_milli,"charge_paise":charge,"cost_allocated":allocate_cost,"recorded_by":actor_id})
    return {"id":identity,"code":code,"contractor_name":contract["contractor_name"],"contract_code":contract["contract_code"],"production_run_code":run["run_code"] if run else "","activity_type":contract["activity_type"],"work_date":work_date,"pay_basis":basis,"unit_label":labor_unit(basis),"quantity":quantity_milli/1000,"rate_per_unit":rupees(contract["rate_paise"]),"charge":rupees(charge),"cost_allocated":allocate_cost,"invoice_ref":invoice_ref,"invoice_doc":doc,"invoice_status":"documented" if doc else "pending"}


def deactivate_user(identity,actor_id):
    if identity==actor_id: raise ValueError("You cannot deactivate your own account")
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        user=db.execute("SELECT id,role,active FROM users WHERE id=?",(identity,)).fetchone()
        if not user: raise ValueError("Account was not found")
        if not user["active"]: return
        if user["role"]=="owner" and db.execute("SELECT COUNT(*) FROM users WHERE active=1 AND role='owner'").fetchone()[0]<=1:
            raise ValueError("The workspace must keep at least one active owner")
        db.execute("UPDATE users SET active=0,updated_at=? WHERE id=?",(now_iso(),identity))
        db.execute("DELETE FROM sessions WHERE user_id=?",(identity,))
        audit(db,"user.deactivated","user",identity,{"deactivated_by":actor_id})


def reset_user_password(identity,password,actor_id):
    password=validate_new_password(password); salt=secrets.token_bytes(16); digest=password_digest(password,salt)
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        user=db.execute("SELECT id,email,active FROM users WHERE id=?",(identity,)).fetchone()
        if not user or not user["active"]: raise ValueError("Active account was not found")
        db.execute("UPDATE users SET password_salt=?,password_hash=?,updated_at=? WHERE id=?",(salt.hex(),digest,now_iso(),identity))
        db.execute("DELETE FROM sessions WHERE user_id=?",(identity,))
        audit(db,"user.password_reset","user",identity,{"reset_by":actor_id})


def bootstrap_for_role(role):
    data=bootstrap()
    if role in ("operations","viewer"):
        data["customers"]=[]
        data["summary"]["customer_count"]=None
        for employee in data["employees"]:
            employee.pop("phone",None); employee.pop("hourly_rate_per_hour",None)
        for entry in data["time_entries"]:
            entry.pop("hourly_rate",None); entry.pop("labor_cost",None)
        for row in data["receipts"]:
            row.pop("rate_per_kg",None); row.pop("invoice_total",None); row.pop("invoice_doc",None)
        for row in data["lots"]: row["cost_per_kg"]=None
        for row in data["runs"]:
            for key in ("labor_cost","energy_cost","electricity_rate_per_kwh","machine_cost_per_hour","machine_cost","total_cost"): row.pop(key,None)
        for machine in data["machines"]:
            machine.pop("machine_cost_per_hour",None); machine.pop("electricity_rate_per_kwh",None)
        for record in data["maintenance_records"]:
            for key in ("cost","invoice_ref","invoice_doc"): record.pop(key,None)
        for contractor in data["contractors"]:
            contractor.pop("phone",None); contractor.pop("contact_name",None)
        for contract in data["labor_contracts"]:
            contract.pop("rate_per_unit",None)
        for item in data["labor_work"]:
            item.pop("rate_per_unit",None); item.pop("charge",None); item.pop("invoice_ref",None); item.pop("invoice_doc",None)
        data["sales"]=[]
        data["summary"]["labor_cost_today"]=None
        data["summary"]["contract_labor_cost_today"]=None
        data["summary"]["contract_labor_cost_month"]=None
        data["summary"]["purchase_total"]=None; data["summary"]["sales_total"]=None; data["summary"]["sales_contribution"]=None
    return data


def lot_trace(identity,role="owner"):
    financial=role in ("owner","finance")
    with conn() as db:
        first=db.execute("SELECT id FROM lots WHERE id=?",(identity,)).fetchone()
        if not first: raise ValueError("Material lot was not found")
        lot_ids=[]; seen_lots=set(); run_ids=set(); pending=[identity]; truncated=False
        while pending:
            current=pending.pop(0)
            if current in seen_lots: continue
            if len(seen_lots)>=500:
                truncated=True; break
            seen_lots.add(current); lot_ids.append(current)
            parent=db.execute("SELECT id,input_lot_id FROM production_runs WHERE output_lot_id=?",(current,)).fetchone()
            if parent:
                run_ids.add(parent["id"]); pending.append(parent["input_lot_id"])
            children=db.execute("SELECT id,output_lot_id FROM production_runs WHERE input_lot_id=? ORDER BY occurred_at,id",(current,)).fetchall()
            for child in children:
                run_ids.add(child["id"]); pending.append(child["output_lot_id"])
        lot_placeholders=','.join('?' for _ in lot_ids)
        lots=[]
        for r in db.execute(f"""SELECT l.id,l.lot_code,l.source_type,l.created_at,l.initial_qty_g,l.cost_per_kg_paise,
             g.code grade_code,g.name grade_name,g.polymer,g.form,g.color,COALESCE(SUM(e.delta_g),0) balance_g
             FROM lots l JOIN grades g ON g.id=l.grade_id LEFT JOIN stock_events e ON e.lot_id=l.id
             WHERE l.id IN ({lot_placeholders}) GROUP BY l.id ORDER BY l.created_at,l.lot_code""",lot_ids):
            item={"id":r["id"],"code":r["lot_code"],"source_type":r["source_type"],"created_at":r["created_at"],"initial_kg":kg(r["initial_qty_g"]),"balance_kg":kg(r["balance_g"]),"grade_code":r["grade_code"],"grade_name":r["grade_name"],"polymer":r["polymer"],"form":r["form"],"color":r["color"]}
            if financial: item["cost_per_kg"]=rupees(r["cost_per_kg_paise"])
            lots.append(item)
        receipt_rows=db.execute(f"""SELECT r.*,s.name supplier,g.name grade,l.lot_code FROM receipts r JOIN suppliers s ON s.id=r.supplier_id
             JOIN grades g ON g.id=r.grade_id JOIN lots l ON l.id=r.lot_id WHERE r.lot_id IN ({lot_placeholders}) ORDER BY r.occurred_at""",lot_ids).fetchall()
        receipts=[]
        for r in receipt_rows:
            item={"id":r["id"],"code":r["receipt_code"],"lot_code":r["lot_code"],"supplier":r["supplier"],"grade":r["grade"],"vehicle_no":r["vehicle_no"],"scale_ticket":r["scale_ticket"],"gross_kg":kg(r["gross_g"]),"tare_kg":kg(r["tare_g"]),"accepted_kg":kg(r["accepted_g"]),"occurred_at":r["occurred_at"],"quality_note":r["quality_note"],"invoice_status":r["invoice_status"]}
            if financial: item.update({"rate_per_kg":rupees(r["rate_paise"]),"invoice_total":rupees(r["invoice_total_paise"]),"invoice_doc":r["invoice_doc"]})
            receipts.append(item)
        run_placeholders=','.join('?' for _ in run_ids)
        runs=[]; run_codes={}
        if run_ids:
            run_rows=db.execute(f"""SELECT p.*,i.lot_code input_lot,ig.name input_grade,o.lot_code output_lot,og.name output_grade
                 FROM production_runs p JOIN lots i ON i.id=p.input_lot_id JOIN grades ig ON ig.id=i.grade_id
                 JOIN lots o ON o.id=p.output_lot_id JOIN grades og ON og.id=o.grade_id
                 WHERE p.id IN ({run_placeholders}) ORDER BY p.occurred_at,p.run_code""",list(run_ids)).fetchall()
            run_by_id={r["id"]:r for r in run_rows}
            producer_by_lot={r["output_lot_id"]:r["id"] for r in run_rows}
            dependencies={r["id"]:set() for r in run_rows}; successors={r["id"]:[] for r in run_rows}
            for r in run_rows:
                producer=producer_by_lot.get(r["input_lot_id"])
                if producer and producer!=r["id"]:
                    dependencies[r["id"]].add(producer); successors[producer].append(r["id"])
            sort_key=lambda run_id:(run_by_id[run_id]["occurred_at"],run_by_id[run_id]["run_code"])
            ready=sorted((run_id for run_id,parents in dependencies.items() if not parents),key=sort_key); ordered_run_ids=[]
            while ready:
                run_id=ready.pop(0); ordered_run_ids.append(run_id)
                for child in successors[run_id]:
                    dependencies[child].discard(run_id)
                    if not dependencies[child] and child not in ordered_run_ids and child not in ready:
                        ready.append(child); ready.sort(key=sort_key)
            ordered_run_ids.extend(sorted(set(run_by_id)-set(ordered_run_ids),key=sort_key))
            run_rows=[run_by_id[run_id] for run_id in ordered_run_ids]
            lot_by_id={l["id"]:l for l in lots}; produced={r["output_lot_id"] for r in run_rows}; lot_children={}
            for r in run_rows: lot_children.setdefault(r["input_lot_id"],[]).append(r["output_lot_id"])
            ordered_lot_ids=[]; visited=set()
            def walk_lots(lot_id):
                if lot_id in visited or lot_id not in lot_by_id: return
                visited.add(lot_id); ordered_lot_ids.append(lot_id)
                for child_lot in lot_children.get(lot_id,[]): walk_lots(child_lot)
            for root_lot in sorted((l["id"] for l in lots if l["id"] not in produced),key=lambda lot_id:(lot_by_id[lot_id]["created_at"],lot_by_id[lot_id]["code"])): walk_lots(root_lot)
            for lot_id in sorted(set(lot_by_id)-visited,key=lambda item:(lot_by_id[item]["created_at"],lot_by_id[item]["code"])): walk_lots(lot_id)
            lots=[lot_by_id[lot_id] for lot_id in ordered_lot_ids]
            for r in run_rows:
                run_codes[r["id"]]=r["run_code"]
                item={"id":r["id"],"code":r["run_code"],"input_lot":r["input_lot"],"input_grade":r["input_grade"],"output_lot":r["output_lot"],"output_grade":r["output_grade"],"input_kg":kg(r["input_g"]),"output_kg":kg(r["output_g"]),"loss_kg":kg(r["loss_g"]),"yield_pct":round(100*r["output_g"]/r["input_g"],1),"machine_label":r["machine_label"],"machine_hours":round(r["machine_hours_milli"]/1000,3),"energy_kwh":round(r["energy_kwh_milli"]/1000,3),"occurred_at":r["occurred_at"]}
                if financial: item.update({"labor_cost":rupees(r["labor_paise"]),"energy_cost":rupees(r["energy_paise"]),"electricity_rate_per_kwh":rupees(r["electricity_rate_paise_per_kwh"]),"machine_cost_per_hour":rupees(r["machine_cost_per_hour_paise"]),"machine_cost":rupees(r["machine_cost_paise"]),"total_cost":rupees(r["total_cost_paise"])})
                runs.append(item)
        lot_codes={l["id"]:l["code"] for l in lots}; events=[]
        for r in db.execute(f"SELECT lot_id,event_type,delta_g,source_type,source_id,note,created_at FROM stock_events WHERE lot_id IN ({lot_placeholders}) ORDER BY created_at,id",lot_ids):
            events.append({"lot_code":lot_codes.get(r["lot_id"],""),"event_type":r["event_type"],"quantity_kg":kg(r["delta_g"]),"source_type":r["source_type"],"source_code":run_codes.get(r["source_id"],""),"note":r["note"],"created_at":r["created_at"]})
        sales=[]
        if financial:
            for r in db.execute(f"""SELECT s.*,l.lot_code,g.name grade,c.name customer FROM sales s JOIN lots l ON l.id=s.lot_id
                 JOIN grades g ON g.id=l.grade_id LEFT JOIN customers c ON c.id=s.customer_id
                 WHERE s.lot_id IN ({lot_placeholders}) ORDER BY s.occurred_at""",lot_ids):
                sales.append({"id":r["id"],"code":r["sale_code"],"lot_code":r["lot_code"],"grade":r["grade"],"customer":r["customer"] or r["customer_name"],"quantity_kg":kg(r["quantity_g"]),"rate_per_kg":rupees(r["rate_paise"]),"invoice_total":rupees(r["invoice_total_paise"]),"cogs":rupees(r["cogs_paise"]),"contribution":rupees(r["invoice_total_paise"]-r["cogs_paise"]),"invoice_doc":r["invoice_doc"],"vehicle_no":r["vehicle_no"],"occurred_at":r["occurred_at"]})
        contractor_work=[]
        if run_ids:
            for r in db.execute(f"""SELECT w.*,c.contract_code,p.name contractor_name,pr.run_code FROM labor_work w
                 JOIN labor_contracts c ON c.id=w.contract_id JOIN contractors p ON p.id=w.contractor_id
                 LEFT JOIN production_runs pr ON pr.id=w.production_run_id
                 WHERE w.production_run_id IN ({run_placeholders}) ORDER BY w.work_date,w.created_at""",list(run_ids)):
                item={"code":r["work_code"],"contract_code":r["contract_code"],"contractor_name":r["contractor_name"],"run_code":r["run_code"],"work_date":r["work_date"],"activity_type":r["activity_type"],"pay_basis":r["pay_basis"],"unit_label":labor_unit(r["pay_basis"]),"quantity":r["quantity_milli"]/1000}
                if financial: item.update({"rate_per_unit":rupees(r["rate_paise"]),"charge":rupees(r["charge_paise"]),"invoice_ref":r["invoice_ref"],"invoice_doc":r["invoice_doc"],"cost_allocated":bool(r["cost_allocated"])})
                contractor_work.append(item)
        main=next(l for l in lots if l["id"]==identity)
        return {"lot":main,"lots":lots,"receipts":receipts,"runs":runs,"events":events,"sales":sales,"contractor_work":contractor_work,"truncated":truncated,"financial":financial}


def create_supplier(data):
    name=str(data.get("name","")).strip()
    if not name: raise ValueError("Supplier name is required")
    if len(name)>120: raise ValueError("Supplier name is too long")
    identity=str(uuid.uuid4()); created=now_iso()
    with conn() as db:
        db.execute("INSERT INTO suppliers(id,name,phone,notes,created_at) VALUES(?,?,?,?,?)",(identity,name,str(data.get("phone","")).strip()[:40],str(data.get("notes","")).strip()[:500],created))
        audit(db,"supplier.created","supplier",identity,{"name":name})
    return {"id":identity,"name":name,"phone":str(data.get("phone","")).strip(),"notes":str(data.get("notes","")).strip(),"created_at":created}


def normalize_customer(data):
    name=str(data.get("name","")).strip()
    if not name: raise ValueError("Customer or business name is required")
    if len(name)>120: raise ValueError("Customer name must be 120 characters or fewer")
    code=str(data.get("customer_code","")).strip().upper() or new_code("CUS")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}",code): raise ValueError("Customer code must use 1–32 letters, numbers, dot, underscore or hyphen")
    contact=str(data.get("contact_name","")).strip(); phone=str(data.get("phone","")).strip(); email=str(data.get("email","")).strip().lower()
    gstin=re.sub(r"\s+","",str(data.get("gstin","")).strip().upper())
    address=str(data.get("billing_address","")).strip()
    if len(contact)>120 or len(phone)>40 or len(email)>254 or len(address)>500: raise ValueError("One or more customer details are too long")
    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email): raise ValueError("Enter a valid customer email address")
    if gstin and not re.fullmatch(r"[0-9]{2}[A-Z0-9]{13}",gstin): raise ValueError("GSTIN must contain 15 characters and begin with a two-digit state code")
    return {"customer_code":code,"name":name,"contact_name":contact,"phone":phone,"email":email,"gstin":gstin,"billing_address":address}


def customer_integrity_error(exc):
    message=str(exc).lower()
    if "customer_code" in message: raise ValueError("That customer code already exists")
    raise ValueError("That GSTIN is already recorded for another customer")


def create_customer(data,actor_id=""):
    fields=normalize_customer(data)
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO customers(id,customer_code,name,contact_name,phone,email,gstin,billing_address,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?,?)",(identity,fields["customer_code"],fields["name"],fields["contact_name"],fields["phone"],fields["email"],fields["gstin"],fields["billing_address"],created,created))
            audit(db,"customer.created","customer",identity,{"customer_code":fields["customer_code"],"name":fields["name"],"created_by":actor_id})
    except sqlite3.IntegrityError as exc:
        customer_integrity_error(exc)
    return {"id":identity,**fields,"active":True,"created_at":created}


def update_customer(identity,data,actor_id=""):
    fields=normalize_customer(data); updated=now_iso()
    try:
        with conn() as db:
            db.execute("BEGIN IMMEDIATE")
            previous=db.execute("SELECT id,customer_code,name FROM customers WHERE id=? AND active=1",(identity,)).fetchone()
            if not previous: raise ValueError("Active customer was not found")
            db.execute("UPDATE customers SET customer_code=?,name=?,contact_name=?,phone=?,email=?,gstin=?,billing_address=?,updated_at=? WHERE id=?",(fields["customer_code"],fields["name"],fields["contact_name"],fields["phone"],fields["email"],fields["gstin"],fields["billing_address"],updated,identity))
            audit(db,"customer.updated","customer",identity,{"before_code":previous["customer_code"],"before_name":previous["name"],"customer_code":fields["customer_code"],"name":fields["name"],"updated_by":actor_id})
    except sqlite3.IntegrityError as exc:
        customer_integrity_error(exc)
    return {"id":identity,**fields,"active":True,"updated_at":updated}


def normalize_grade(data):
    name=str(data.get("name","")).strip(); code=str(data.get("code","")).strip().upper()
    polymer=str(data.get("polymer","")).strip().upper(); form=str(data.get("form","")).strip(); color=str(data.get("color","")).strip()
    if not all((name,code,polymer,form)): raise ValueError("Grade name, code, polymer and form are required")
    if len(code)>32 or not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]*",code): raise ValueError("Grade code may use letters, numbers, dot, underscore and hyphen")
    if len(name)>100 or len(polymer)>20 or len(form)>30 or len(color)>30: raise ValueError("Grade name, polymer, form or color exceeds its allowed length")
    return {"name":name,"code":code,"polymer":polymer,"form":form,"color":color}


def create_grade(data):
    fields=normalize_grade(data)
    identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO grades VALUES(?,?,?,?,?,?,1,?)",(identity,fields["code"],fields["name"],fields["polymer"],fields["form"],fields["color"],created))
            audit(db,"grade.created","grade",identity,{"code":fields["code"],"name":fields["name"]})
    except sqlite3.IntegrityError: raise ValueError("That grade code already exists")
    return {"id":identity,**fields,"active":1}


def import_grades(data,actor_id=""):
    rows=data.get("grades")
    if not isinstance(rows,list) or not rows: raise ValueError("Choose a CSV file with at least one grade row")
    if len(rows)>250: raise ValueError("Import up to 250 grade rows at a time")
    normalized=[]; seen=set()
    for index,row in enumerate(rows,start=2):
        if not isinstance(row,dict): raise ValueError(f"Row {index}: expected a grade record")
        try: grade=normalize_grade(row)
        except ValueError as exc: raise ValueError(f"Row {index}: {exc}")
        key=grade["code"].casefold()
        if key in seen: raise ValueError(f"Row {index}: grade code {grade['code']} appears more than once in this file")
        seen.add(key); normalized.append(grade)
    created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        existing={row["code"].casefold() for row in db.execute("SELECT code FROM grades")}
        to_add=[grade for grade in normalized if grade["code"].casefold() not in existing]
        skipped=[grade["code"] for grade in normalized if grade["code"].casefold() in existing]
        for grade in to_add:
            identity=str(uuid.uuid4())
            db.execute("INSERT INTO grades VALUES(?,?,?,?,?,?,1,?)",(identity,grade["code"],grade["name"],grade["polymer"],grade["form"],grade["color"],created))
            audit(db,"grade.created","grade",identity,{"code":grade["code"],"name":grade["name"],"imported_by":actor_id})
        if to_add:
            audit(db,"grades.imported","grade_import",str(uuid.uuid4()),{"created_count":len(to_add),"skipped_codes":skipped,"imported_by":actor_id})
    skipped_text=(" Existing codes skipped: "+", ".join(skipped)+".") if skipped else ""
    return {"created_count":len(to_add),"skipped_codes":skipped,"message":f"{len(to_add)} grades imported; {len(skipped)} existing codes skipped.{skipped_text}"}


def create_receipt(data):
    supplier_id=str(data.get("supplier_id", "")); grade_id=str(data.get("grade_id", ""))
    vehicle=re.sub(r"\s+"," ",str(data.get("vehicle_no", "")).strip().upper())
    gross=as_int_kg(data.get("gross_kg"),"gross weight"); tare=as_int_kg(data.get("tare_kg"),"tare weight",allow_zero=True)
    accepted=as_int_kg(data.get("accepted_kg"),"accepted weight"); rate=as_paise(data.get("rate_per_kg"),"purchase rate",allow_zero=True)
    amount=as_paise(data.get("invoice_total",0),"invoice amount",allow_zero=True); status=str(data.get("invoice_status","pending"))
    if gross<=tare: raise ValueError("Gross weight must be greater than tare weight")
    if accepted>gross-tare: raise ValueError("Accepted weight cannot exceed net weighbridge weight")
    if not vehicle: raise ValueError("Vehicle registration is required")
    if status not in ("pending","documented"): raise ValueError("Invoice status must be pending or documented")
    quality_note=str(data.get("quality_note", "")).strip()[:300]
    if gross-tare>accepted and not quality_note:
        raise ValueError("Add a short quality or rejection reason because accepted weight is below net weight")
    doc=safe_document_path(data.get("invoice_doc", "")); ticket=str(data.get("scale_ticket", "")).strip()[:80]
    if status == "documented" and not doc: raise ValueError("Attach the invoice before marking it documented")
    if status == "pending" and doc: raise ValueError("An attached invoice must be marked documented")
    occurred=as_timestamp(data.get("occurred_at", now_iso()),"weighment time")
    identity=str(uuid.uuid4()); lot_id=str(uuid.uuid4()); code=new_code("RCV"); lot_code=new_code("LOT"); created=now_iso()
    with conn() as db:
        if not db.execute("SELECT 1 FROM suppliers WHERE id=?",(supplier_id,)).fetchone(): raise ValueError("Select a valid supplier")
        if not db.execute("SELECT 1 FROM grades WHERE id=? AND active=1",(grade_id,)).fetchone(): raise ValueError("Select an active material grade")
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO lots VALUES(?,?,?,?,?,?,?,?,?)",(lot_id,lot_code,grade_id,"receipt",identity,created,accepted,rate,"available"))
        db.execute("INSERT INTO stock_events(id,lot_id,event_type,delta_g,source_type,source_id,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),lot_id,"receipt",accepted,"receipt",identity,"Accepted material received",created))
        db.execute("INSERT INTO receipts(id,receipt_code,supplier_id,grade_id,lot_id,vehicle_no,gross_g,tare_g,accepted_g,rate_paise,invoice_total_paise,invoice_status,invoice_doc,scale_ticket,occurred_at,created_at,quality_note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(identity,code,supplier_id,grade_id,lot_id,vehicle,gross,tare,accepted,rate,amount,status,doc,ticket,occurred,created,quality_note))
        audit(db,"receipt.created","receipt",identity,{"receipt_code":code,"lot_code":lot_code,"vehicle_no":vehicle,"accepted_g":accepted,"invoice_status":status,"quality_note":quality_note})
    return {"id":identity,"code":code,"lot_code":lot_code}


MACHINE_AREAS={"grading","grinding","baling","sorting","washing","other"}
MAINTENANCE_TYPES={"preventive","repair","breakdown","inspection","cleaning","other"}


def normalize_machine(data):
    code=str(data.get("machine_code","")).strip().upper() or new_code("MCH")
    name=str(data.get("name","")).strip()
    area=str(data.get("process_area","")).strip().lower()
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}",code): raise ValueError("Machine code must use 1–32 letters, numbers, dot, underscore or hyphen")
    if not name or len(name)>120: raise ValueError("Enter a machine name (up to 120 characters)")
    if area not in MACHINE_AREAS: raise ValueError("Choose grading, grinding, baling, sorting, washing or other")
    rated_power=as_milli_nonnegative(data.get("rated_power_kw"),"rated power in kW")
    hourly_cost=as_paise(data.get("machine_cost_per_hour",0),"machine cost per hour",allow_zero=True)
    electricity_rate=as_paise(data.get("electricity_rate_per_kwh",0),"electricity rate per kWh",allow_zero=True)
    notes=str(data.get("notes","")).strip()[:400]
    active=str(data.get("active",True)).strip().lower() not in {"0","false","no","off"}
    return {"machine_code":code,"name":name,"process_area":area,"rated_power_kw_milli":rated_power,"machine_cost_per_hour_paise":hourly_cost,"electricity_rate_paise_per_kwh":electricity_rate,"active":int(active),"notes":notes}


def create_machine(data,actor_id):
    fields=normalize_machine(data); identity=str(uuid.uuid4()); created=now_iso()
    try:
        with conn() as db:
            db.execute("INSERT INTO machines(id,machine_code,name,process_area,rated_power_kw_milli,machine_cost_per_hour_paise,electricity_rate_paise_per_kwh,active,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(identity,fields["machine_code"],fields["name"],fields["process_area"],fields["rated_power_kw_milli"],fields["machine_cost_per_hour_paise"],fields["electricity_rate_paise_per_kwh"],fields["active"],fields["notes"],created,created))
            audit(db,"machine.created","machine",identity,{"machine_code":fields["machine_code"],"machine_cost_per_hour_paise":fields["machine_cost_per_hour_paise"],"electricity_rate_paise_per_kwh":fields["electricity_rate_paise_per_kwh"],"created_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("That machine code already exists")
    return {"id":identity,"machine_code":fields["machine_code"],"name":fields["name"],"process_area":fields["process_area"],"rated_power_kw":round(fields["rated_power_kw_milli"]/1000,3),"machine_cost_per_hour":rupees(fields["machine_cost_per_hour_paise"]),"electricity_rate_per_kwh":rupees(fields["electricity_rate_paise_per_kwh"]),"active":bool(fields["active"]),"notes":fields["notes"],"created_at":created}


def update_machine(identity,data,actor_id):
    fields=normalize_machine(data); updated=now_iso()
    try:
        with conn() as db:
            prior=db.execute("SELECT id FROM machines WHERE id=?",(identity,)).fetchone()
            if not prior: raise ValueError("Machine was not found")
            db.execute("UPDATE machines SET machine_code=?,name=?,process_area=?,rated_power_kw_milli=?,machine_cost_per_hour_paise=?,electricity_rate_paise_per_kwh=?,active=?,notes=?,updated_at=? WHERE id=?",(fields["machine_code"],fields["name"],fields["process_area"],fields["rated_power_kw_milli"],fields["machine_cost_per_hour_paise"],fields["electricity_rate_paise_per_kwh"],fields["active"],fields["notes"],updated,identity))
            audit(db,"machine.updated","machine",identity,{"machine_code":fields["machine_code"],"machine_cost_per_hour_paise":fields["machine_cost_per_hour_paise"],"electricity_rate_paise_per_kwh":fields["electricity_rate_paise_per_kwh"],"active":bool(fields["active"]),"updated_by":actor_id})
    except sqlite3.IntegrityError: raise ValueError("That machine code already exists")
    return {"id":identity,"machine_code":fields["machine_code"],"name":fields["name"],"process_area":fields["process_area"],"rated_power_kw":round(fields["rated_power_kw_milli"]/1000,3),"machine_cost_per_hour":rupees(fields["machine_cost_per_hour_paise"]),"electricity_rate_per_kwh":rupees(fields["electricity_rate_paise_per_kwh"]),"active":bool(fields["active"]),"notes":fields["notes"],"updated_at":updated}


def create_maintenance(data,actor_id,allow_cost_entry=True):
    machine_id=str(data.get("machine_id","")).strip()
    work_type=str(data.get("work_type","")).strip().lower()
    status=str(data.get("status","completed")).strip().lower()
    work_date=valid_date(data.get("work_date"),"service date")
    next_due=str(data.get("next_due_date","")).strip()
    if next_due:
        next_due=valid_date(next_due,"next service date")
        if next_due<work_date: raise ValueError("Next service date cannot be before the recorded service date")
    if work_type not in MAINTENANCE_TYPES: raise ValueError("Choose a supported maintenance type")
    if status not in {"planned","completed"}: raise ValueError("Choose planned or completed maintenance")
    downtime=as_milli_nonnegative(data.get("downtime_hours"),"downtime hours")
    cost=as_paise(data.get("cost",0),"maintenance cost",allow_zero=True)
    invoice_ref=str(data.get("invoice_ref","")).strip()
    if len(invoice_ref)>80: raise ValueError("Invoice reference must be 80 characters or fewer")
    doc=safe_document_path(data.get("invoice_doc","")); notes=str(data.get("notes","")).strip()[:500]
    if not allow_cost_entry and (cost or invoice_ref or doc): raise ValueError("Only owner or finance users can enter maintenance cost or invoice evidence")
    identity=str(uuid.uuid4()); code=new_code("MNT"); created=now_iso()
    with conn() as db:
        if not db.execute("SELECT 1 FROM machines WHERE id=?",(machine_id,)).fetchone(): raise ValueError("Choose a registered machine")
        db.execute("INSERT INTO maintenance_records(id,maintenance_code,machine_id,work_type,status,work_date,next_due_date,downtime_hours_milli,cost_paise,invoice_ref,invoice_doc,notes,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(identity,code,machine_id,work_type,status,work_date,next_due,downtime,cost,invoice_ref,doc,notes,actor_id,created))
        audit(db,"machine.maintenance_recorded","maintenance_record",identity,{"maintenance_code":code,"machine_id":machine_id,"work_type":work_type,"status":status,"cost_paise":cost,"recorded_by":actor_id})
    return {"id":identity,"code":code,"machine_id":machine_id,"work_type":work_type,"status":status,"work_date":work_date,"next_due_date":next_due,"downtime_hours":round(downtime/1000,3),"cost":rupees(cost),"invoice_ref":invoice_ref,"invoice_doc":doc,"notes":notes,"created_at":created}


def complete_maintenance(identity,data,actor_id,allow_cost_entry=True):
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        current=db.execute("SELECT * FROM maintenance_records WHERE id=?",(identity,)).fetchone()
        if not current: raise ValueError("Maintenance record was not found")
        if current["status"]!="planned": raise ValueError("Only planned maintenance can be marked complete")
        if "cost" in data:
            cost=as_paise(data.get("cost"),"maintenance cost",allow_zero=True)
        else: cost=current["cost_paise"]
        invoice_ref=str(data.get("invoice_ref",current["invoice_ref"])).strip()
        if len(invoice_ref)>80: raise ValueError("Invoice reference must be 80 characters or fewer")
        doc=safe_document_path(data.get("invoice_doc",current["invoice_doc"]))
        if not allow_cost_entry and (("cost" in data and cost!=current["cost_paise"]) or invoice_ref!=current["invoice_ref"] or doc!=current["invoice_doc"]):
            raise ValueError("Only owner or finance users can enter maintenance cost or invoice evidence")
        downtime=as_milli_nonnegative(data["downtime_hours"],"downtime hours") if "downtime_hours" in data else current["downtime_hours_milli"]
        next_due=str(data.get("next_due_date",current["next_due_date"])).strip()
        if next_due:
            next_due=valid_date(next_due,"next service date")
            if next_due<current["work_date"]: raise ValueError("Next service date cannot be before the recorded service date")
        notes=str(data.get("notes",current["notes"])).strip()[:500]
        db.execute("UPDATE maintenance_records SET status='completed',next_due_date=?,downtime_hours_milli=?,cost_paise=?,invoice_ref=?,invoice_doc=?,notes=? WHERE id=?",(next_due,downtime,cost,invoice_ref,doc,notes,identity))
        audit(db,"machine.maintenance_completed","maintenance_record",identity,{"maintenance_code":current["maintenance_code"],"cost_paise":cost,"completed_by":actor_id})
    return {"id":identity,"status":"completed","next_due_date":next_due,"downtime_hours":round(downtime/1000,3),"cost":rupees(cost),"invoice_ref":invoice_ref,"invoice_doc":doc,"notes":notes}


def create_run(data,allow_financial_override=True):
    source_id=str(data.get("input_lot_id","")); output_grade_id=str(data.get("output_grade_id",""))
    input_g=as_int_kg(data.get("input_kg"),"input quantity"); output_g=as_int_kg(data.get("output_kg"),"output quantity")
    labor=as_paise(data.get("labor_cost",0),"labour cost",allow_zero=True)
    machine_id=str(data.get("machine_id","")).strip() or None
    machine_hours=as_milli_nonnegative(data.get("machine_hours"),"machine hours")
    energy_kwh=as_milli_nonnegative(data.get("energy_kwh"),"electricity usage in kWh")
    manual_energy=as_paise(data.get("energy_cost",0),"electricity cost",allow_zero=True)
    electricity_rate_value=str(data.get("electricity_rate_per_kwh","")).strip()
    if not allow_financial_override and (manual_energy or electricity_rate_value): raise ValueError("Only owner or finance users can enter or override production costs")
    if energy_kwh and manual_energy: raise ValueError("Enter measured kWh and a rate, or enter a manual electricity amount, not both")
    if machine_hours and not machine_id: raise ValueError("Choose the machine used for this run")
    if output_g>input_g: raise ValueError("Output cannot exceed the input quantity")
    occurred=as_timestamp(data.get("occurred_at",now_iso()),"production time"); note=str(data.get("note","")).strip()[:500]
    identity=str(uuid.uuid4()); out_id=str(uuid.uuid4()); run_code=new_code("RUN"); lot_code=new_code("LOT"); created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        source=db.execute("SELECT l.*,g.name grade FROM lots l JOIN grades g ON g.id=l.grade_id WHERE l.id=?",(source_id,)).fetchone()
        if not source: raise ValueError("Select a valid input lot")
        if not db.execute("SELECT 1 FROM grades WHERE id=? AND active=1",(output_grade_id,)).fetchone(): raise ValueError("Select an active output grade")
        machine=db.execute("SELECT id,machine_code,name,machine_cost_per_hour_paise,electricity_rate_paise_per_kwh FROM machines WHERE id=? AND active=1",(machine_id,)).fetchone() if machine_id else None
        if machine_id and not machine: raise ValueError("Choose an active registered machine")
        machine_rate=machine["machine_cost_per_hour_paise"] if machine else 0
        machine_cost=int((Decimal(machine_hours)*Decimal(machine_rate)/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        machine_label=f"{machine['machine_code']} · {machine['name']}" if machine else ""
        electricity_rate=0
        if energy_kwh:
            if electricity_rate_value:
                electricity_rate=as_paise(electricity_rate_value,"electricity rate per kWh",allow_zero=True)
            elif machine and machine["electricity_rate_paise_per_kwh"]>0:
                electricity_rate=machine["electricity_rate_paise_per_kwh"]
            else:
                raise ValueError("Choose a machine with a saved electricity rate or enter the rate per kWh")
            energy=int((Decimal(energy_kwh)*Decimal(electricity_rate)/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        else:
            energy=manual_energy
        available=current_stock(db,source_id)
        if input_g>available: raise ValueError(f"Only {kg(available):.3f} kg is available in that lot")
        material_cost=int((Decimal(input_g)*Decimal(source["cost_per_kg_paise"])/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        total=material_cost+labor+energy+machine_cost; unit_cost=int((Decimal(total)*Decimal(1000)/Decimal(output_g)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        loss=input_g-output_g
        db.execute("INSERT INTO lots VALUES(?,?,?,?,?,?,?,?,?)",(out_id,lot_code,output_grade_id,"production",identity,created,output_g,unit_cost,"available"))
        db.execute("INSERT INTO stock_events(id,lot_id,event_type,delta_g,source_type,source_id,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),source_id,"production_consumption",-input_g,"production_run",identity,"Input issued to production",created))
        db.execute("INSERT INTO stock_events(id,lot_id,event_type,delta_g,source_type,source_id,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),out_id,"production_output",output_g,"production_run",identity,"Finished output created",created))
        db.execute("""INSERT INTO production_runs(id,run_code,input_lot_id,output_lot_id,output_grade_id,input_g,output_g,loss_g,labor_paise,energy_paise,material_cost_paise,total_cost_paise,occurred_at,note,created_at,machine_id,machine_label,machine_hours_milli,machine_cost_per_hour_paise,machine_cost_paise,energy_kwh_milli,electricity_rate_paise_per_kwh)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(identity,run_code,source_id,out_id,output_grade_id,input_g,output_g,loss,labor,energy,material_cost,total,occurred,note,created,machine_id,machine_label,machine_hours,machine_rate,machine_cost,energy_kwh,electricity_rate))
        audit(db,"production.completed","production_run",identity,{"run_code":run_code,"input_g":input_g,"output_g":output_g,"machine_id":machine_id,"machine_hours_milli":machine_hours,"machine_cost_paise":machine_cost,"energy_kwh_milli":energy_kwh,"electricity_rate_paise_per_kwh":electricity_rate,"cost_paise":total})
    return {"id":identity,"code":run_code,"output_lot":lot_code,"yield_pct":round(100*output_g/input_g,1),"machine_label":machine_label,"machine_hours":round(machine_hours/1000,3),"machine_cost":rupees(machine_cost),"energy_kwh":round(energy_kwh/1000,3),"energy_cost":rupees(energy),"total_cost":rupees(total)}


def create_sale(data):
    requested_customer_id=str(data.get("customer_id", "")).strip(); legacy_customer_name=str(data.get("customer_name", "")).strip(); lot_id=str(data.get("lot_id", "")); quantity=as_int_kg(data.get("quantity_kg"),"dispatch quantity")
    rate=as_paise(data.get("rate_per_kg"),"selling rate"); vehicle=re.sub(r"\s+"," ",str(data.get("vehicle_no","")).strip().upper())
    doc=safe_document_path(data.get("invoice_doc", "")); occurred=as_timestamp(data.get("occurred_at",now_iso()),"dispatch time")
    if len(legacy_customer_name)>120: raise ValueError("Customer name is too long")
    identity=str(uuid.uuid4()); code=new_code("SAL"); created=now_iso()
    with conn() as db:
        db.execute("BEGIN IMMEDIATE")
        if requested_customer_id:
            customer=db.execute("SELECT id,name FROM customers WHERE id=? AND active=1",(requested_customer_id,)).fetchone()
        elif legacy_customer_name:
            customer=db.execute("SELECT id,name FROM customers WHERE name=? COLLATE NOCASE AND active=1 ORDER BY created_at LIMIT 1",(legacy_customer_name,)).fetchone()
        else:
            customer=None
        if not customer: raise ValueError("Select an active customer from the customer register")
        customer_id,customer_name=customer["id"],customer["name"]
        lot=db.execute("SELECT * FROM lots WHERE id=?",(lot_id,)).fetchone()
        if not lot: raise ValueError("Select a valid finished goods lot")
        if lot["source_type"]!="production": raise ValueError("Sales dispatch is currently limited to produced finished goods")
        available=current_stock(db,lot_id)
        if quantity>available: raise ValueError(f"Only {kg(available):.3f} kg is available in that lot")
        invoice_total=int((Decimal(quantity)*Decimal(rate)/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        cogs=int((Decimal(quantity)*Decimal(lot["cost_per_kg_paise"])/Decimal(1000)).quantize(Decimal("1"),rounding=ROUND_HALF_UP))
        db.execute("INSERT INTO sales(id,sale_code,customer_name,lot_id,quantity_g,rate_paise,invoice_total_paise,cogs_paise,invoice_doc,vehicle_no,occurred_at,created_at,customer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(identity,code,customer_name,lot_id,quantity,rate,invoice_total,cogs,doc,vehicle,occurred,created,customer_id))
        db.execute("INSERT INTO stock_events(id,lot_id,event_type,delta_g,source_type,source_id,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),lot_id,"sale_dispatch",-quantity,"sale",identity,"Finished goods dispatched",created))
        audit(db,"sale.dispatched","sale",identity,{"sale_code":code,"customer_id":customer_id,"quantity_g":quantity,"invoice_total_paise":invoice_total,"cogs_paise":cogs})
    return {"id":identity,"code":code,"customer_id":customer_id,"customer_name":customer_name,"invoice_total":rupees(invoice_total),"contribution":rupees(invoice_total-cogs)}


class Handler(BaseHTTPRequestHandler):
    server_version = "ScrapFacilityMVP/0.1"
    def log_message(self, fmt, *args): print(f"[{self.log_date_time_string()}] {fmt % args}")
    def send_json(self, payload, status=200, headers=None):
        body=json.dumps(payload,ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.security_headers()
        for key,value in (headers or {}).items(): self.send_header(key,value)
        self.end_headers(); self.wfile.write(body)
    def security_headers(self):
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","same-origin")
        self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    def send_bytes(self,body,content_type,status=200,headers=None):
        self.send_response(status); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(body))); self.security_headers()
        for key,value in (headers or {}).items(): self.send_header(key,value)
        self.end_headers(); self.wfile.write(body)
    def request_session(self):
        cookie=SimpleCookie()
        try: cookie.load(self.headers.get("Cookie", ""))
        except Exception: return None
        morsel=cookie.get("scrap_session")
        return session_for_token(morsel.value) if morsel else None
    def csrf_valid(self,session):
        provided=self.headers.get("X-CSRF-Token", "")
        return bool(provided and hmac.compare_digest(provided,session["csrf_token"]))
    def origin_valid(self):
        origin=self.headers.get("Origin")
        if not origin: return True
        try: return urlparse(origin).netloc==self.headers.get("Host", "")
        except Exception: return False
    def session_response(self,result):
        raw=result.pop("token")
        cookie=f"scrap_session={raw}; Path=/; Max-Age={SESSION_MAX_AGE}; HttpOnly; SameSite=Strict"
        if os.environ.get("SCRAP_APP_COOKIE_SECURE", "").lower() in ("1","true","yes"): cookie += "; Secure"
        return self.send_json({"authenticated":True,"user":result["user"],"csrf_token":result["csrf_token"]},headers={"Set-Cookie":cookie})
    def read_json(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>MAX_BODY: raise ApiError("Request is too large",413)
        try: data=json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError: raise ApiError("Invalid JSON body")
        if not isinstance(data,dict): raise ApiError("Expected a JSON object")
        return data
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/auth/status":
            session=self.request_session()
            return self.send_json({"setup_required":not users_exist(),"authenticated":bool(session),"user":session["user"] if session else None,"csrf_token":session["csrf_token"] if session else ""})
        trace_match=re.fullmatch(r"/api/lots/([0-9a-f-]{36})/trace",path)
        if trace_match:
            session=self.request_session()
            if not session: return self.send_json({"error":"Sign in to continue"},401)
            try: return self.send_json(lot_trace(trace_match.group(1),session["user"]["role"]))
            except ValueError as e: return self.send_json({"error":str(e)},404)
            except Exception: return self.send_json({"error":"Could not load lot trace"},500)
        if path=="/api/users":
            session=self.request_session()
            if not session: return self.send_json({"error":"Sign in to continue"},401)
            if session["user"]["role"]!="owner": return self.send_json({"error":"Only the workspace owner can manage accounts"},403)
            return self.send_json({"users":list_users()})
        if path=="/api/bootstrap":
            session=self.request_session()
            if not session: return self.send_json({"error":"Sign in to continue"},401)
            try: return self.send_json(bootstrap_for_role(session["user"]["role"]))
            except Exception as e: return self.send_json({"error":"Could not load workspace data"},500)
        if path.startswith("/documents/"):
            if not self.request_session(): return self.send_json({"error":"Sign in to view this document"},401)
            name=path.split("/",2)[-1]
            if not re.fullmatch(r"[a-f0-9-]+\.(jpg|png|pdf|webp)",name): return self.send_json({"error":"Not found"},404)
            file=(UPLOAD_DIR/name).resolve()
            if file.parent!=UPLOAD_DIR.resolve() or not file.is_file(): return self.send_json({"error":"Not found"},404)
            content_type=mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            return self.send_bytes(file.read_bytes(),content_type,headers={"Cache-Control":"private, no-store"})
        if path=="/" or path=="/index.html":
            file=ROOT/"static"/"index.html"; content=file.read_bytes()
            return self.send_bytes(content,"text/html; charset=utf-8",headers={"Cache-Control":"no-store"})
        if path in STATIC_TYPES:
            file=ROOT/"static"/path.lstrip("/"); content=file.read_bytes()
            cache="no-store" if path in ("/app.css","/app.js") else "public, max-age=86400"
            return self.send_bytes(content,STATIC_TYPES[path],headers={"Cache-Control":cache})
        return self.send_json({"error":"Not found"},404)
    def do_POST(self):
        path=urlparse(self.path).path
        try:
            if path in ("/api/auth/setup","/api/auth/login"):
                if not self.origin_valid(): return self.send_json({"error":"Invalid request origin"},403)
                data=self.read_json()
                result=create_first_owner(data) if path=="/api/auth/setup" else login_user(data,self.client_address[0])
                return self.session_response(result)
            session=self.request_session()
            if not session: return self.send_json({"error":"Your session has expired. Please sign in again."},401)
            if not self.csrf_valid(session): return self.send_json({"error":"Session verification failed. Refresh and try again."},403)
            if path=="/api/auth/logout":
                with conn() as db: db.execute("DELETE FROM sessions WHERE token_hash=?",(session["token_hash"],))
                return self.send_json({"ok":True},headers={"Set-Cookie":"scrap_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            role=session["user"]["role"]
            customer_update=re.fullmatch(r"/api/customers/([0-9a-f-]{36})",path)
            if customer_update:
                if role not in ("owner","finance"): return self.send_json({"error":"Your account does not have permission for this action"},403)
                return self.send_json(update_customer(customer_update.group(1),self.read_json(),session["user"]["id"]))
            machine_update=re.fullmatch(r"/api/machines/([0-9a-f-]{36})",path)
            if machine_update:
                if role not in ("owner","finance"): return self.send_json({"error":"Your account does not have permission for this action"},403)
                return self.send_json(update_machine(machine_update.group(1),self.read_json(),session["user"]["id"]))
            maintenance_complete=re.fullmatch(r"/api/maintenance/([0-9a-f-]{36})/complete",path)
            if maintenance_complete:
                if role not in ("owner","finance","operations"): return self.send_json({"error":"Your account does not have permission for this action"},403)
                result=complete_maintenance(maintenance_complete.group(1),self.read_json(),session["user"]["id"],allow_cost_entry=role in ("owner","finance"))
                if role=="operations":
                    for key in ("cost","invoice_ref","invoice_doc"): result.pop(key,None)
                return self.send_json(result)
            password_reset=re.fullmatch(r"/api/users/([0-9a-f-]{36})/password",path)
            if password_reset:
                if role!="owner": return self.send_json({"error":"Only the workspace owner can manage accounts"},403)
                data=self.read_json()
                reset_user_password(password_reset.group(1),data.get("password"),session["user"]["id"])
                return self.send_json({"ok":True})
            role_policy={
              "/api/suppliers":{"owner","finance"}, "/api/grades":{"owner","finance"},
              "/api/customers":{"owner","finance"}, "/api/grades/import":{"owner","finance"},
              "/api/receipts":{"owner","finance","operations"}, "/api/production-runs":{"owner","operations"},
              "/api/sales":{"owner","finance"}, "/api/documents":{"owner","finance","operations"},
              "/api/users":{"owner"}, "/api/employees":{"owner","finance"},
              "/api/time-entries":{"owner","finance","operations"},
              "/api/contractors":{"owner","finance"}, "/api/labor-contracts":{"owner","finance"},
              "/api/labor-work":{"owner","finance","operations"}
            }
            role_policy["/api/machines"]={"owner","finance"}
            role_policy["/api/maintenance"]={"owner","finance","operations"}
            if path not in role_policy: return self.send_json({"error":"Not found"},404)
            if role not in role_policy[path]: return self.send_json({"error":"Your account does not have permission for this action"},403)
            data=self.read_json()
            if path=="/api/suppliers": return self.send_json(create_supplier(data),201)
            if path=="/api/customers": return self.send_json(create_customer(data,session["user"]["id"]),201)
            if path=="/api/grades": return self.send_json(create_grade(data),201)
            if path=="/api/grades/import": return self.send_json(import_grades(data,session["user"]["id"]),201)
            if path=="/api/receipts": return self.send_json(create_receipt(data),201)
            if path=="/api/production-runs":
                result=create_run(data,allow_financial_override=role in ("owner","finance"))
                if role in ("operations","viewer"):
                    for key in ("machine_cost","energy_cost","total_cost"): result.pop(key,None)
                return self.send_json(result,201)
            if path=="/api/sales": return self.send_json(create_sale(data),201)
            if path=="/api/documents": return self.send_json(self.save_document(data),201)
            if path=="/api/users": return self.send_json(create_staff_user(data,session["user"]["id"]),201)
            if path=="/api/employees": return self.send_json(create_employee(data,session["user"]["id"]),201)
            if path=="/api/time-entries": return self.send_json(create_time_entry(data,session["user"]["id"]),201)
            if path=="/api/contractors": return self.send_json(create_contractor(data,session["user"]["id"]),201)
            if path=="/api/labor-contracts": return self.send_json(create_labor_contract(data,session["user"]["id"]),201)
            if path=="/api/labor-work":
                requested_allocation=str(data.get("allocate_cost","")).strip().lower() in {"1","true","yes","on"}
                if requested_allocation and role not in ("owner","finance"):
                    return self.send_json({"error":"Only owner or finance users can allocate contractor charges to production cost"},403)
                result=create_labor_work(data,session["user"]["id"],allow_cost_allocation=role in ("owner","finance"))
                if role=="operations":
                    for key in ("rate_per_unit","charge","invoice_ref","invoice_doc"): result.pop(key,None)
                return self.send_json(result,201)
            if path=="/api/machines": return self.send_json(create_machine(data,session["user"]["id"]),201)
            if path=="/api/maintenance":
                result=create_maintenance(data,session["user"]["id"],allow_cost_entry=role in ("owner","finance"))
                if role=="operations":
                    for key in ("cost","invoice_ref","invoice_doc"): result.pop(key,None)
                return self.send_json(result,201)
        except ValueError as e: return self.send_json({"error":str(e)},400)
        except sqlite3.IntegrityError as e: return self.send_json({"error":"The record could not be saved due to a data conflict"},409)
        except ApiError as e: return self.send_json({"error":e.message},e.status)
        except Exception as e:
            print(f"Unhandled error: {e}"); return self.send_json({"error":"Unexpected server error"},500)
    def do_DELETE(self):
        path=urlparse(self.path).path
        match=re.fullmatch(r"/api/users/([0-9a-f-]{36})",path)
        if not match: return self.send_json({"error":"Not found"},404)
        session=self.request_session()
        if not session: return self.send_json({"error":"Your session has expired. Please sign in again."},401)
        if not self.csrf_valid(session): return self.send_json({"error":"Session verification failed. Refresh and try again."},403)
        if session["user"]["role"]!="owner": return self.send_json({"error":"Only the workspace owner can manage accounts"},403)
        try:
            deactivate_user(match.group(1),session["user"]["id"])
            return self.send_json({"ok":True})
        except ValueError as e: return self.send_json({"error":str(e)},400)
        except Exception as e:
            print(f"Unhandled error: {e}"); return self.send_json({"error":"Unexpected server error"},500)
    def save_document(self,data):
        mime=str(data.get("mime_type","")); name=str(data.get("name","document")); encoded=data.get("data_base64","")
        if mime not in MIME_EXT: raise ValueError("Attach a JPG, PNG, WebP image or PDF")
        if not isinstance(encoded,str) or len(encoded)>MAX_BODY*1.4: raise ApiError("File is too large",413)
        import base64, binascii
        try: raw=base64.b64decode(encoded,validate=True)
        except (binascii.Error,ValueError): raise ValueError("Invalid document data")
        if not raw or len(raw)>8*1024*1024: raise ApiError("Document must be under 8 MB",413)
        signature_ok={"image/jpeg":raw.startswith(b"\xff\xd8\xff"),"image/png":raw.startswith(b"\x89PNG\r\n\x1a\n"),"application/pdf":raw.startswith(b"%PDF-"),"image/webp":len(raw)>12 and raw[:4]==b"RIFF" and raw[8:12]==b"WEBP"}[mime]
        if not signature_ok: raise ValueError("File content does not match its type")
        stored=f"{uuid.uuid4()}{MIME_EXT[mime]}"; (UPLOAD_DIR/stored).write_bytes(raw)
        return {"path":f"/documents/{stored}","name":name[:180],"mime_type":mime,"size":len(raw)}


if __name__=="__main__":
    initialize()
    host=os.environ.get("SCRAP_APP_HOST","127.0.0.1"); port=int(os.environ.get("SCRAP_APP_PORT","8000"))
    remote=host not in ("127.0.0.1","localhost","::1")
    secure_cookie=os.environ.get("SCRAP_APP_COOKIE_SECURE", "").lower() in ("1","true","yes")
    if remote and (os.environ.get("SCRAP_APP_ALLOW_REMOTE")!="1" or not secure_cookie):
        raise SystemExit("Remote binding is disabled. Use an HTTPS reverse proxy, Secure cookies, and SCRAP_APP_ALLOW_REMOTE=1 before binding beyond localhost.")
    print(f"Scrap Facility MVP running at http://{host}:{port}")
    print(f"Database: {DB_PATH}")
    ThreadingHTTPServer((host,port),Handler).serve_forever()
