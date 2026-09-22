from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import date, datetime
import os
import uuid
import mysql.connector
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def db():
    return mysql.connector.connect(
        host=app.config["DB_HOST"],
        user=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        database=app.config["DB_NAME"]
    )

def query(sql, params=(), fetch=False, many=False):
    conn = db()
    cur = conn.cursor(dictionary=True)
    try:
        if many:
            cur.executemany(sql, params)
        else:
            cur.execute(sql, params)
        result = cur.fetchall() if fetch else None
        conn.commit()
        return result
    finally:
        cur.close()
        conn.close()

def audit(action, table_name=None, record_id=None, description=""):
    uid = session.get("user_id")
    query("""INSERT INTO audit_logs
             (user_id, action, table_name, record_id, description, ip_address)
             VALUES (%s,%s,%s,%s,%s,%s)""",
          (uid, action, table_name, record_id, description,
           request.remote_addr))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                return "Forbidden", 403
            return fn(*args, **kwargs)
        return wrapper
    return deco

def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def land_by_id(land_id):
    rows = query("SELECT * FROM lands WHERE land_id=%s", (land_id,), True)
    return rows[0] if rows else None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        rows = query("SELECT * FROM users WHERE username=%s AND is_active=1",
                     (username,), True)
        if rows and check_password_hash(rows[0]["password_hash"], password):
            u = rows[0]
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["role"] = u["role"]
            audit("LOGIN")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if session.get("user_id"):
        audit("LOGOUT")
    session.clear()
    return redirect(url_for("index"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    # Disable this route after creating the first admin in a real deployment.
    count = query("SELECT COUNT(*) AS c FROM users", fetch=True)[0]["c"]
    if count > 0:
        return "Setup disabled because users already exist.", 403
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        name = request.form["full_name"].strip()
        query("""INSERT INTO users(username,password_hash,role,full_name)
                 VALUES(%s,%s,'GOVT',%s)""",
              (username, generate_password_hash(password), name))
        return redirect(url_for("login"))
    return render_template("setup.html")

@app.route("/dashboard")
@login_required
def dashboard():
    stats = {}
    stats["total"] = query("SELECT COUNT(*) c FROM lands", fetch=True)[0]["c"]
    stats["acquisition"] = query(
        "SELECT COUNT(*) c FROM lands WHERE land_status='UNDER_ACQUISITION'", fetch=True
    )[0]["c"]
    stats["completed"] = query(
        "SELECT COUNT(*) c FROM lands WHERE land_status='ACQUISITION_COMPLETED'", fetch=True
    )[0]["c"]
    stats["court"] = query(
        "SELECT COUNT(*) c FROM lands WHERE land_status IN ('DISPUTED','COURT_CASE')", fetch=True
    )[0]["c"]
    stats["police"] = query(
        "SELECT COUNT(*) c FROM lands WHERE land_status='POLICE_ACTION'", fetch=True
    )[0]["c"]
    stats["delayed"] = query(
        "SELECT COUNT(*) c FROM acquisition WHERE delay_days > 0", fetch=True
    )[0]["c"]
    return render_template("dashboard.html", stats=stats)

@app.route("/lands")
@login_required
def lands():
    q = request.args.get("q", "").strip()
    if q:
        pattern = f"%{q}%"
        rows = query("""SELECT * FROM lands
                        WHERE land_id LIKE %s OR survey_no LIKE %s
                        OR owner_name LIKE %s OR village LIKE %s
                        OR district LIKE %s
                        ORDER BY updated_at DESC""",
                     (pattern, pattern, pattern, pattern, pattern), True)
    else:
        rows = query("SELECT * FROM lands ORDER BY updated_at DESC", fetch=True)
    return render_template("lands.html", lands=rows, q=q)

@app.route("/lands/add", methods=["GET", "POST"])
@role_required("GOVT", "COURT", "POLICE")
def add_land():
    if request.method == "POST":
        land_id = request.form["land_id"].strip()
        query("""INSERT INTO lands
            (land_id,survey_no,owner_name,village,district,state,latitude,longitude,
             land_status,ownership_verification,acquisition_authority,
             acquisition_notification_date,compensation_status,responsible_department,
             public_warning)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            tuple(request.form.get(k) or None for k in [
                "land_id","survey_no","owner_name","village","district","state",
                "latitude","longitude","land_status","ownership_verification",
                "acquisition_authority","acquisition_notification_date",
                "compensation_status","responsible_department","public_warning"
            ]))
        audit("CREATE", "lands", None, f"Created land {land_id}")
        flash("Land created.")
        return redirect(url_for("land_detail", land_id=land_id))
    return render_template("land_form.html")

@app.route("/land/<land_id>")
@login_required
def land_detail(land_id):
    land = land_by_id(land_id)
    if not land:
        return "Land not found", 404
    court = query("""SELECT * FROM court_cases WHERE land_id=%s
                     ORDER BY filing_date DESC""",
                  (land["id"],), True)
    police = query("""SELECT id,complaint_type,complaint_date,status,
                      investigating_authority,date_opened,date_closed,
                      relevant_actions,public_status,public_visible
                      FROM police_complaints WHERE land_id=%s
                      ORDER BY complaint_date DESC""",
                   (land["id"],), True)
    acquisitions = query("""SELECT * FROM acquisition WHERE land_id=%s
                            ORDER BY start_date DESC""",
                         (land["id"],), True)
    docs = query("""SELECT * FROM documents WHERE land_id=%s
                    ORDER BY category, version_no DESC""",
                 (land["id"],), True)
    timeline = query("""SELECT 'COURT' source, ce.event_date event_date,
                        ce.event_type title, ce.description
                        FROM court_events ce JOIN court_cases cc ON cc.id=ce.case_id
                        WHERE cc.land_id=%s
                        UNION ALL
                        SELECT 'ACQUISITION', a.start_date, a.stage,
                               CONCAT(a.status, ' - ', COALESCE(a.reason_for_delay,''))
                        FROM acquisition a WHERE a.land_id=%s
                        ORDER BY event_date DESC""",
                     (land["id"], land["id"]), True)
    active_cases = sum(1 for x in court if x["current_status"] not in
                       ("CLOSED", "DISPOSED", "COMPLETED"))
    stay = any(x["stay_order"] for x in court)
    risk = "LOW"
    if stay or land["land_status"] in ("DISPUTED","COURT_CASE"):
        risk = "HIGH"
    elif active_cases or land["land_status"] == "UNDER_ACQUISITION":
        risk = "CAUTION"
    return render_template("land_detail.html", land=land, court=court, police=police,
                           acquisitions=acquisitions, docs=docs, timeline=timeline,
                           risk=risk)

@app.route("/public/search")
def public_search():
    q = request.args.get("q", "").strip()
    rows = []
    if q:
        p = f"%{q}%"
        rows = query("""SELECT land_id,survey_no,village,district,state,land_status,
                        ownership_verification,public_warning,updated_at
                        FROM lands
                        WHERE land_id LIKE %s OR survey_no LIKE %s
                        OR village LIKE %s OR district LIKE %s
                        LIMIT 50""",
                     (p,p,p,p), True)
    return render_template("public_search.html", lands=rows, q=q)

@app.route("/public/land/<land_id>")
def public_land(land_id):
    land = land_by_id(land_id)
    if not land:
        return "Land not found", 404

    court = query("""SELECT case_number,court_name,filing_date,case_type,
                     current_status,next_hearing_date,dispute_type,stay_order,
                     public_summary
                     FROM court_cases
                     WHERE land_id=%s AND public_summary IS NOT NULL""",
                  (land["id"],), True)
    police = query("""SELECT complaint_type,complaint_date,status,public_status
                      FROM police_complaints
                      WHERE land_id=%s AND public_visible=1""",
                   (land["id"],), True)
    acq = query("""SELECT stage,start_date,completion_date,responsible_authority,
                   status,delay_days,reason_for_delay,next_action,deadline
                   FROM acquisition WHERE land_id=%s
                   ORDER BY start_date DESC""",
                (land["id"],), True)
    active_cases = [c for c in court if c["current_status"] not in
                    ("CLOSED","DISPOSED","COMPLETED")]
    stay = any(c["stay_order"] for c in court)
    if stay:
        risk, summary = "HIGH", "An active court order/stay may affect this land."
    elif active_cases or land["land_status"] == "UNDER_ACQUISITION":
        risk, summary = "CAUTION", "Review the active proceedings and acquisition information before proceeding."
    else:
        risk, summary = "LOW", "No active publicly recorded court dispute or acquisition proceeding was found."
    return render_template("public_land.html", land=land, court=court, police=police,
                           acq=acq, risk=risk, summary=summary)

@app.route("/court/case/add/<land_id>", methods=["GET", "POST"])
@role_required("COURT", "GOVT")
def add_case(land_id):
    land = land_by_id(land_id)
    if not land: return "Land not found", 404
    if request.method == "POST":
        cur_conn = db()
        cur = cur_conn.cursor()
        cur.execute("""INSERT INTO court_cases
            (land_id,case_number,court_name,parties,filing_date,case_type,
             current_status,current_proceedings,next_hearing_date,case_outcome,
             dispute_type,stay_order,public_summary,created_by)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (land["id"], request.form["case_number"], request.form["court_name"],
             request.form["parties"], request.form["filing_date"] or None,
             request.form["case_type"], request.form["current_status"],
             request.form["current_proceedings"], request.form["next_hearing_date"] or None,
             request.form["case_outcome"], request.form["dispute_type"],
             request.form.get("stay_order") == "on", request.form["public_summary"],
             session["user_id"]))
        case_id = cur.lastrowid
        cur_conn.commit(); cur.close(); cur_conn.close()
        audit("CREATE", "court_cases", case_id, f"Case {request.form['case_number']}")
        query("UPDATE lands SET land_status=%s WHERE id=%s",
              ("COURT_CASE" if request.form["stay_order"] != "on" else "DISPUTED", land["id"]))
        return redirect(url_for("land_detail", land_id=land_id))
    return render_template("case_form.html", land=land)

@app.route("/police/complaint/add/<land_id>", methods=["GET", "POST"])
@role_required("POLICE", "GOVT")
def add_complaint(land_id):
    land = land_by_id(land_id)
    if not land: return "Land not found", 404
    if request.method == "POST":
        query("""INSERT INTO police_complaints
            (land_id,complaint_type,complaint_date,status,investigating_authority,
             date_opened,date_closed,relevant_actions,public_status,
             public_visible,confidential_details,created_by)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (land["id"], request.form["complaint_type"],
             request.form["complaint_date"] or None, request.form["status"],
             request.form["investigating_authority"],
             request.form["date_opened"] or None, request.form["date_closed"] or None,
             request.form["relevant_actions"], request.form["public_status"],
             request.form.get("public_visible") == "on",
             request.form["confidential_details"], session["user_id"]))
        audit("CREATE", "police_complaints", None, f"Complaint on {land_id}")
        query("UPDATE lands SET land_status=%s WHERE id=%s",
              ("POLICE_ACTION", land["id"]))
        return redirect(url_for("land_detail", land_id=land_id))
    return render_template("complaint_form.html", land=land)

@app.route("/acquisition/add/<land_id>", methods=["GET", "POST"])
@role_required("GOVT")
def add_acquisition(land_id):
    land = land_by_id(land_id)
    if not land: return "Land not found", 404
    if request.method == "POST":
        query("""INSERT INTO acquisition
            (land_id,stage,start_date,completion_date,responsible_authority,
             status,delay_days,reason_for_delay,next_action,deadline,document_notes,created_by)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (land["id"], request.form["stage"], request.form["start_date"] or None,
             request.form["completion_date"] or None, request.form["responsible_authority"],
             request.form["status"], int(request.form["delay_days"] or 0),
             request.form["reason_for_delay"], request.form["next_action"],
             request.form["deadline"] or None, request.form["document_notes"],
             session["user_id"]))
        audit("CREATE", "acquisition", None, f"Acquisition update for {land_id}")
        query("UPDATE lands SET land_status='UNDER_ACQUISITION' WHERE id=%s",
              (land["id"],))
        return redirect(url_for("land_detail", land_id=land_id))
    return render_template("acquisition_form.html", land=land)

@app.route("/documents/upload/<land_id>", methods=["POST"])
@role_required("COURT", "POLICE", "GOVT")
def upload_document(land_id):
    land = land_by_id(land_id)
    f = request.files.get("document")
    if not land or not f or not f.filename or not allowed_file(f.filename):
        return "Invalid file or land", 400
    ext = f.filename.rsplit(".",1)[1].lower()
    stored = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    latest = query("""SELECT COALESCE(MAX(version_no),0)+1 v
                      FROM documents WHERE land_id=%s AND category=%s""",
                   (land["id"], request.form["category"]), True)[0]["v"]
    query("""INSERT INTO documents
             (land_id,category,original_name,stored_name,version_no,
              public_visible,uploaded_by)
             VALUES(%s,%s,%s,%s,%s,%s,%s)""",
          (land["id"], request.form["category"], secure_filename(f.filename),
           stored, latest, request.form.get("public_visible") == "on",
           session["user_id"]))
    audit("UPLOAD", "documents", None, f"Uploaded {f.filename} for {land_id}")
    return redirect(url_for("land_detail", land_id=land_id))

@app.route("/documents/<path:name>")
@login_required
def document_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

@app.route("/api/land/<land_id>")
def land_api(land_id):
    land = land_by_id(land_id)
    if not land:
        return jsonify({"error":"not_found"}), 404
    # Public API intentionally returns only public-safe fields.
    return jsonify({
        "land_id": land["land_id"],
        "survey_no": land["survey_no"],
        "village": land["village"],
        "district": land["district"],
        "state": land["state"],
        "land_status": land["land_status"],
        "ownership_verification": land["ownership_verification"],
        "public_warning": land["public_warning"],
        "last_updated": land["updated_at"].isoformat() if land["updated_at"] else None
    })

if __name__ == "__main__":
    app.run(debug=True)
