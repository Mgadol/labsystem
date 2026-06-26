from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from models import get_db, init_db, hash_password, check_password
from datetime import datetime, date
from functools import wraps
import os, uuid, io, secrets, time
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ── SECRET KEY: instance/-д хадгалагдана, автоматаар үүснэ ────
_KEY_FILE = os.path.join(os.path.dirname(__file__), 'instance', 'secret_key')
os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE, 'rb') as _f:
        app.secret_key = _f.read()
else:
    _k = secrets.token_bytes(32)
    with open(_KEY_FILE, 'wb') as _f:
        _f.write(_k)
    app.secret_key = _k

# ── SESSION COOKIE АЮУЛГҮЙ ТОХИРГОО ───────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = False  # HTTPS ашиглах үед True болгоно
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ── LOGIN BRUTE-FORCE ХАМГААЛАЛТ ──────────────────────────────
_login_attempts = {}   # {ip: [timestamp, ...]}
_LOGIN_MAX   = 5       # дээд тоо
_LOGIN_WINDOW = 300    # 5 минут (секундээр)
_LOGIN_BLOCK  = 600    # 10 минут блоклоно

def _get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

def _is_blocked(ip):
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    return len(attempts) >= _LOGIN_MAX

def _record_fail(ip):
    now = time.time()
    _login_attempts.setdefault(ip, []).append(now)

def _clear_attempts(ip):
    _login_attempts.pop(ip, None)

# ── SECURITY HEADERS ──────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options']  = 'nosniff'
    resp.headers['X-Frame-Options']          = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection']         = '1; mode=block'
    resp.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']       = 'geolocation=(), microphone=(), camera=()'
    return resp

ALLOWED = {'png','jpg','jpeg','gif','webp','pdf','doc','docx'}

def allowed(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED

def save_file(file, subfolder):
    if file and file.filename and allowed(file.filename):
        ext  = file.filename.rsplit('.',1)[1].lower()
        name = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(path, exist_ok=True)
        dest = os.path.join(path, name)
        # Зураг бол чанарыг хадгалан оновчтой хэмжээнд resize хийнэ
        if ext in ('jpg','jpeg','png','webp'):
            try:
                from PIL import Image as PILImage, ExifTags
                img = PILImage.open(file.stream)
                # EXIF rotation засах
                try:
                    for key, val in ExifTags.TAGS.items():
                        if val == 'Orientation':
                            exif = img._getexif()
                            if exif and key in exif:
                                ori = exif[key]
                                if ori == 3:   img = img.rotate(180, expand=True)
                                elif ori == 6: img = img.rotate(270, expand=True)
                                elif ori == 8: img = img.rotate(90,  expand=True)
                            break
                except Exception:
                    pass
                # Профайл зураг: max 800px хадгалах (чанар алдахгүй)
                if subfolder == 'staff':
                    img.thumbnail((800, 1000), PILImage.LANCZOS)
                else:
                    img.thumbnail((1200, 1200), PILImage.LANCZOS)
                save_ext = 'JPEG' if ext in ('jpg','jpeg') else ext.upper()
                img.save(dest, save_ext, quality=92, optimize=True)
            except Exception:
                file.stream.seek(0)
                file.save(dest)
        else:
            file.save(dest)
        return f"{subfolder}/{name}"
    return None

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if 'user_id' not in session and session.get('role') != 'guest':
            return redirect(url_for('login'))
        if session.get('role') == 'guest' and request.method == 'POST':
            flash('Зочин горимд өөрчлөлт хийх боломжгүй.', 'error')
            return redirect(request.referrer or url_for('dashboard'))
        return f(*a, **kw)
    return dec

def guest_block(f):
    """Guest горимд POST үйлдлийг хаах"""
    @wraps(f)
    def dec(*a, **kw):
        if session.get('role') == 'guest' and request.method == 'POST':
            flash('Зочин горимд өөрчлөлт хийх боломжгүй.', 'error')
            return redirect(request.referrer or url_for('dashboard'))
        return f(*a, **kw)
    return dec

def admin_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Админы эрх шаардлагатай.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return dec

def senior_required(f):
    """Админ + Ахлах химич хоёулан нэвтэрч болно"""
    @wraps(f)
    def dec(*a, **kw):
        if session.get('role') == 'guest':
            if request.method == 'POST':
                flash('Зочин горимд өөрчлөлт хийх боломжгүй.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
            return f(*a, **kw)
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') not in ('admin', 'senior'):
            flash('Ахлах химич эсвэл админы эрх шаардлагатай.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return dec

def lab_required(f):
    """Лабын бүх ажилтан (senior, staff, preparer)"""
    @wraps(f)
    def dec(*a, **kw):
        if session.get('role') == 'guest':
            if request.method == 'POST':
                flash('Зочин горимд өөрчлөлт хийх боломжгүй.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
            return f(*a, **kw)
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') not in ('admin', 'senior', 'staff', 'preparer'):
            flash('Лабын ажилтны эрх шаардлагатай.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return dec

def preparer_required(f):
    """Дээж бэлтгэгч + дээш"""
    @wraps(f)
    def dec(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') not in ('admin', 'senior', 'staff', 'preparer'):
            flash('Дээж бэлтгэгчийн эрх шаардлагатай.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return dec

def get_user(user_id):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return u

@app.context_processor
def inject_user():
    user = None
    if session.get('role') == 'guest':
        user = {'id': 0, 'name': 'Зочин', 'role': 'guest', 'photo': None,
                'employee_id': 'GUEST', 'position': 'Зочин', 'phone': None,
                'email': None, 'joined_date': None, 'is_active': 1}
    elif 'user_id' in session:
        user = get_user(session.get('user_id', 0))
    return dict(current_user=user, now=datetime.now())

# ── AUTH ────────────────────────────────────────────────
@app.route('/', methods=['GET','POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    lang = request.args.get('lang', session.get('lang','mn'))
    session['lang'] = lang
    error = None
    if request.method == 'POST':
        lang = request.form.get('lang','mn')
        session['lang'] = lang
        ip = _get_ip()
        if _is_blocked(ip):
            error = 'Хэт олон удаа буруу оруулсан. 10 минутын дараа дахин оролдоно уу.'
            return render_template('auth/login.html', error=error, lang=lang)
        emp_id = request.form.get('employee_id','').strip()
        pw     = request.form.get('password','')
        conn   = get_db()
        u = conn.execute("SELECT * FROM users WHERE (employee_id=? OR name=?) AND is_active=1",(emp_id,emp_id)).fetchone()
        conn.close()
        if u and check_password(u['password_hash'], pw):
            _clear_attempts(ip)
            session['user_id'] = u['id']
            session['role']    = u['role']
            return redirect(url_for('dashboard'))
        _record_fail(ip)
        remaining = _LOGIN_MAX - len(_login_attempts.get(ip, []))
        error = f'Нэвтрэх нэр эсвэл нууц үг буруу. ({max(0,remaining)} оролдлого үлдлээ)'
    return render_template('auth/login.html', error=error, lang=lang)

@app.route('/guest/<token>')
def guest_login(token):
    conn = get_db()
    now = datetime.now().isoformat()
    # Хугацаа дууссан токенуудыг устгана
    conn.execute("DELETE FROM guest_tokens WHERE expires_at < ?", (now,))
    conn.commit()
    row = conn.execute("SELECT * FROM guest_tokens WHERE token=? AND expires_at >= ?", (token.upper(), now)).fetchone()
    conn.close()
    if not row:
        return render_template('auth/login.html', error='Зочны код хүчингүй болсон эсвэл буруу байна.', lang='mn'), 403
    session['user_id'] = 0
    session['role'] = 'guest'
    session['lang'] = 'mn'
    session['guest_label'] = row['label'] or ''
    return redirect(url_for('dashboard'))

@app.route('/guest/token/delete/<int:tid>', methods=['POST'])
@admin_required
def guest_token_delete(tid):
    conn = get_db()
    conn.execute("DELETE FROM guest_tokens WHERE id=?", (tid,))
    conn.commit(); conn.close()
    flash('Зочны код устгагдлаа.', 'success')
    return redirect(url_for('lab_settings') + '?tab=guest')

@app.route('/guest/generate', methods=['POST'])
@admin_required
def guest_token_generate():
    import random, string
    label = request.form.get('label', '').strip() or 'Зочин'
    token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    from datetime import timedelta
    expires_at = (datetime.now().replace(microsecond=0) + timedelta(hours=24)).isoformat()
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS guest_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        label TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL
    )""")
    try:
        conn.execute("INSERT INTO guest_tokens (token, label, created_by, expires_at) VALUES (?,?,?,?)",
                     (token, label, session['user_id'], expires_at))
        conn.commit()
        flash(f'Зочны код үүслээ: {token}  (24 цаг хүчинтэй, {expires_at[:16]} хүртэл)', 'success')
    except Exception as e:
        flash(f'Алдаа гарлаа: {e}', 'error')
    conn.close()
    return redirect(url_for('lab_settings') + '?tab=guest')

@app.route('/logout')
def logout():
    # Тоногийн ашиглалт хаах
    if 'user_id' in session:
        try:
            now = datetime.now().isoformat()
            conn = get_db()
            conn.execute("""UPDATE device_usage_log
                           SET ended_at=?,
                               duration_min=ROUND((JULIANDAY(?)-JULIANDAY(started_at))*1440,1)
                           WHERE user_id=? AND ended_at IS NULL""",
                        (now, now, session['user_id']))
            conn.commit()
            conn.close()
        except: pass
    session.clear()
    return redirect(url_for('login'))

@app.route('/lang/<lang>')
def set_lang(lang):
    session['lang'] = lang if lang in ('mn','en') else 'mn'
    ref = request.referrer
    return redirect(ref if ref else url_for('dashboard'))

# ── DASHBOARD ───────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    lang = session.get('lang','mn')
    conn = get_db()
    if session.get('role') in ('admin', 'senior', 'guest'):
        devices  = conn.execute("SELECT d.*, dm.manufacturer, dm.model FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id ORDER BY d.name").fetchall()
        users    = conn.execute("SELECT * FROM users WHERE is_active=1 AND role NOT IN ('geologist','bayjuulach')").fetchall()
        clients  = conn.execute("SELECT * FROM users WHERE is_active=1 AND role IN ('geologist','bayjuulach')").fetchall()
        open_rep = conn.execute("SELECT COUNT(*) as c FROM repairs WHERE status='new'").fetchone()['c']
        today    = date.today().isoformat()
        expiring = conn.execute("""
            SELECT d.id, d.name, c.next_date,
                   CAST(julianday(c.next_date) - julianday(?) AS INTEGER) as days
            FROM devices d
            JOIN calibrations c ON c.device_id=d.id
            WHERE c.id=(SELECT id FROM calibrations WHERE device_id=d.id ORDER BY calibration_date DESC LIMIT 1)
            AND days<=30 ORDER BY days
        """, (today,)).fetchall()
        my_devices, active_map = [], {}
        if session.get('role') == 'senior':
            uid = session.get('user_id', 0)
            my_devices = conn.execute("""
                SELECT d.*, dm.manufacturer, dm.model FROM devices d
                LEFT JOIN device_marks dm ON d.mark_id=dm.id
                JOIN staff_device_permissions p ON p.device_id=d.id
                WHERE p.user_id=? ORDER BY d.name
            """, (uid,)).fetchall()
            active_logs = conn.execute("SELECT * FROM usage_logs WHERE user_id=? AND end_time IS NULL", (uid,)).fetchall()
            active_map = {r['device_id']: r for r in active_logs}
        conn.close()
        return render_template('admin/dashboard.html',
            devices=devices, users=users, clients=clients, open_rep=open_rep, expiring=expiring,
            my_devices=my_devices, active_map=active_map, lang=lang)
    else:
        uid = session.get('user_id', 0)
        if session.get('role') == 'bayjuulach':
            user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            samples = conn.execute("""
                SELECT sr.id as receipt_id, sr.lab_number, sr.lab_serial, sr.received_date,
                       g.sample_name, g.sample_type, g.status
                FROM sample_receipt sr
                JOIN geo_samples g ON g.id=sr.geo_sample_id
                WHERE g.status='done' AND sr.lab_serial BETWEEN 6000 AND 6999
                ORDER BY sr.lab_serial DESC LIMIT 100
            """).fetchall() if (user and user['can_view_result']) else []
            conn.close()
            return render_template('staff/dashboard_bayjuulach.html',
                user=user, samples=samples, lang=lang)
        my_devices = conn.execute("""
            SELECT d.*, dm.manufacturer, dm.model FROM devices d
            LEFT JOIN device_marks dm ON d.mark_id=dm.id
            JOIN staff_device_permissions p ON p.device_id=d.id
            WHERE p.user_id=? ORDER BY d.name
        """, (uid,)).fetchall()
        active_logs = conn.execute("SELECT * FROM usage_logs WHERE user_id=? AND end_time IS NULL", (uid,)).fetchall()
        conn.close()
        active_map = {r['device_id']: r for r in active_logs}
        return render_template('staff/dashboard.html',
            devices=my_devices, active_map=active_map, lang=lang)

# ── DEVICES ─────────────────────────────────────────────
@app.route('/devices')
@login_required
def devices():
    lang = session.get('lang','mn')
    conn = get_db()
    if session.get('role') == 'admin':
        devs = conn.execute("""
            SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d
            LEFT JOIN device_marks dm ON d.mark_id=dm.id
            ORDER BY (d.lab_id IS NULL OR d.lab_id=''), d.lab_id, d.name
        """).fetchall()
    else:
        devs = conn.execute("""
            SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d
            LEFT JOIN device_marks dm ON d.mark_id=dm.id
            JOIN staff_device_permissions p ON p.device_id=d.id
            WHERE p.user_id=?
            ORDER BY (d.lab_id IS NULL OR d.lab_id=''), d.lab_id, d.name
        """, (session.get('user_id', 0),)).fetchall()
    # Хэрэглэгчийн бүх идэвхтэй ашиглалт (олон төхөөрөмж зэрэг ашиглаж болно)
    active_rows = conn.execute("SELECT id, device_id FROM usage_logs WHERE user_id=? AND end_time IS NULL",
                          (session.get('user_id', 0),)).fetchall()
    conn.close()
    # device_id → log_id харгалзаа
    active_map = {r['device_id']: r['id'] for r in active_rows}
    return render_template('device/list.html', devices=devs, lang=lang,
        active_map=active_map)

@app.route('/devices/<int:did>')
@login_required
def device_detail(did):
    lang = session.get('lang','mn')
    conn = get_db()
    device = conn.execute("SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id WHERE d.id=?", (did,)).fetchone()
    if not device:
        conn.close(); return redirect(url_for('devices'))
    if session.get('role') != 'admin':
        perm = conn.execute("SELECT 1 FROM staff_device_permissions WHERE user_id=? AND device_id=?", (session.get('user_id', 0), did)).fetchone()
        if not perm:
            conn.close()
            flash('Энэ төхөөрөмжид хандах эрх байхгүй.', 'error')
            return redirect(url_for('devices'))
    cals   = conn.execute("SELECT c.*, u.name as uname FROM calibrations c LEFT JOIN users u ON u.id=c.performed_by WHERE c.device_id=? ORDER BY c.calibration_date DESC LIMIT 20", (did,)).fetchall()
    reps   = conn.execute("SELECT r.*, u.name as uname FROM repairs r LEFT JOIN users u ON u.id=r.reported_by WHERE r.device_id=? ORDER BY r.reported_date DESC LIMIT 20", (did,)).fetchall()
    logs   = conn.execute("SELECT ul.*, u.name as uname FROM usage_logs ul LEFT JOIN users u ON u.id=ul.user_id WHERE ul.device_id=? ORDER BY ul.start_time DESC LIMIT 50", (did,)).fetchall()
    active = conn.execute("SELECT * FROM usage_logs WHERE device_id=? AND end_time IS NULL", (did,)).fetchone()
    # Monthly hours
    now = datetime.now()
    mhours = conn.execute("""
        SELECT COALESCE(SUM(duration_hours),0) as total FROM usage_logs
        WHERE device_id=? AND strftime('%Y-%m', start_time)=?
    """, (did, now.strftime('%Y-%m'))).fetchone()['total']
    analysis_usage = conn.execute("""
        SELECT u.id as user_id, u.name as user_name,
               COUNT(*) as sessions,
               COALESCE(SUM(CAST((julianday(ul.end_time)-julianday(ul.start_time))*1440 AS INTEGER)),0) as total_min,
               MAX(ul.start_time) as last_used
        FROM usage_logs ul
        JOIN users u ON u.id=ul.user_id
        WHERE ul.device_id=? AND ul.end_time IS NOT NULL
        GROUP BY u.id ORDER BY total_min DESC
    """, (did,)).fetchall()
    checks = [dict(r) for r in conn.execute("""
        SELECT ch.*, u.name as uname FROM device_checks ch
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE ch.device_id=? ORDER BY ch.check_date DESC, ch.id DESC LIMIT 60
    """, (did,)).fetchall()]
    calib_checks = []
    try:
        calib_checks = [dict(r) for r in conn.execute("""
            SELECT cc.*, u.name as uname FROM device_calib_checks cc
            LEFT JOIN users u ON u.id=cc.checked_by
            WHERE cc.device_id=? ORDER BY cc.check_date DESC LIMIT 24
        """, (did,)).fetchall()]
    except Exception: pass
    cal_checks = []
    try:
        cal_checks = [dict(r) for r in conn.execute("""
            SELECT cc.*, u.name as uname FROM device_calorimeter_checks cc
            LEFT JOIN users u ON u.id=cc.checked_by
            WHERE cc.device_id=? ORDER BY cc.check_date DESC LIMIT 24
        """, (did,)).fetchall()]
    except Exception: pass
    conn.close()
    return render_template('device/detail.html',
        device=device, calibrations=cals, repairs=reps,
        usage_logs=logs, active_log=active, checks=checks,
        calib_checks=calib_checks, cal_checks=cal_checks,
        monthly_hours=round(mhours,2),
        analysis_usage=analysis_usage,
        lang=lang, today=date.today().isoformat())

def _resolve_mark(conn, manufacturer, model, category):
    """Үйлдвэрлэгч/загвараар mark олох, байхгүй бол шинээр үүсгэж id буцаана."""
    manufacturer = (manufacturer or '').strip()
    model = (model or '').strip()
    category = (category or '').strip() or None
    if not manufacturer and not model:
        return None
    row = conn.execute(
        "SELECT id FROM device_marks WHERE manufacturer=? AND model=?",
        (manufacturer, model)).fetchone()
    if row:
        return row['id']
    cur = conn.execute(
        "INSERT INTO device_marks(manufacturer,model,category) VALUES(?,?,?)",
        (manufacturer, model, category))
    return cur.lastrowid

@app.route('/devices/add', methods=['GET','POST'])
@senior_required
def device_add():
    lang = session.get('lang','mn')
    conn = get_db()
    marks = conn.execute("SELECT * FROM device_marks ORDER BY manufacturer").fetchall()
    if request.method == 'POST':
        photo = save_file(request.files.get('photo'), 'devices')
        pdf   = save_file(request.files.get('passport_pdf'), 'passports')
        # Үйлдвэрлэгч/загвараас mark олох эсвэл шинээр үүсгэх
        mark_id = _resolve_mark(conn,
            request.form.get('manufacturer'),
            request.form.get('model'),
            request.form.get('category'))
        conn.execute("""
            INSERT INTO devices(name,serial_number,mark_id,location,purchase_date,
            warranty_expiry,calibration_interval,photo,passport_pdf,status,notes,
            lab_id,web_link,method,max_temp,particular,measuring_time,measuring_limit,
            dimension,capacity,weight_kg,other_spec,power,frequency,voltage,
            specification,operating_state,received_date,
            check_param1,check_standard,check_tolerance,
            check_param2,check_standard2,check_tolerance2,
            check_param3,check_standard3,check_tolerance3,
            check_param4,check_standard4,check_tolerance4,
            check_param5,check_standard5,check_tolerance5,
            check_enabled,stage,check_freq)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            request.form['name'],
            request.form.get('serial_number') or None,
            mark_id,
            request.form.get('location'),
            request.form.get('purchase_date') or None,
            request.form.get('warranty_expiry') or None,
            int(request.form.get('calibration_interval') or 90),
            photo, pdf, 'active',
            request.form.get('notes'),
            request.form.get('lab_id') or None,
            request.form.get('web_link') or None,
            request.form.get('method') or None,
            request.form.get('max_temp') or None,
            request.form.get('particular') or None,
            request.form.get('measuring_time') or None,
            request.form.get('measuring_limit') or None,
            request.form.get('dimension') or None,
            request.form.get('capacity') or None,
            request.form.get('weight_kg') or None,
            request.form.get('other_spec') or None,
            request.form.get('power') or None,
            request.form.get('frequency') or None,
            request.form.get('voltage') or None,
            request.form.get('specification') or None,
            request.form.get('operating_state') or None,
            request.form.get('received_date') or None,
            request.form.get('check_param1') or None,
            request.form.get('check_standard') or None,
            request.form.get('check_tolerance') or None,
            request.form.get('check_param2') or None,
            request.form.get('check_standard2') or None,
            request.form.get('check_tolerance2') or None,
            request.form.get('check_param3') or None,
            request.form.get('check_standard3') or None,
            request.form.get('check_tolerance3') or None,
            request.form.get('check_param4') or None,
            request.form.get('check_standard4') or None,
            request.form.get('check_tolerance4') or None,
            request.form.get('check_param5') or None,
            request.form.get('check_standard5') or None,
            request.form.get('check_tolerance5') or None,
            1 if request.form.get('check_enabled') else 0,
            request.form.get('stage') or 'both',
            request.form.get('check_freq') or 'daily',
        ))
        did = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit(); conn.close()
        flash('Төхөөрөмж нэмэгдлээ!' if lang=='mn' else 'Device added!', 'success')
        return redirect(url_for('device_detail', did=did))
    conn.close()
    return render_template('device/add.html', marks=marks, lang=lang)

@app.route('/devices/<int:did>/edit', methods=['GET','POST'])
@senior_required
def device_edit(did):
    lang = session.get('lang','mn')
    conn = get_db()
    device = conn.execute("SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id WHERE d.id=?", (did,)).fetchone()
    marks  = conn.execute("SELECT * FROM device_marks").fetchall()
    if request.method == 'POST':
        # Зөвхөн шалгалтын тохиргоо хадгалах (check tab-аас дуудагдана)
        if request.form.get('_check_config_only'):
            try:
                conn.execute("""UPDATE devices SET
                    check_group1=?, check_group2=?, check_group3=?,
                    check_param1=?, check_standard=?, check_tolerance=?,
                    check_param2=?, check_standard2=?, check_tolerance2=?,
                    check_param3=?, check_standard3=?, check_tolerance3=?,
                    check_param4=?, check_standard4=?, check_tolerance4=?,
                    check_param5=?, check_standard5=?, check_tolerance5=?,
                    check_group1_cols=?, check_group2_cols=?, check_group3_cols=?
                    WHERE id=?""", (
                    request.form.get('check_group1') or None,
                    request.form.get('check_group2') or None,
                    request.form.get('check_group3') or None,
                    request.form.get('check_param1') or None,
                    request.form.get('check_standard') or None,
                    request.form.get('check_tolerance') or None,
                    request.form.get('check_param2') or None,
                    request.form.get('check_standard2') or None,
                    request.form.get('check_tolerance2') or None,
                    request.form.get('check_param3') or None,
                    request.form.get('check_standard3') or None,
                    request.form.get('check_tolerance3') or None,
                    request.form.get('check_param4') or None,
                    request.form.get('check_standard4') or None,
                    request.form.get('check_tolerance4') or None,
                    request.form.get('check_param5') or None,
                    request.form.get('check_standard5') or None,
                    request.form.get('check_tolerance5') or None,
                    int(request.form.get('check_group1_cols') or 2),
                    int(request.form.get('check_group2_cols') or 1),
                    int(request.form.get('check_group3_cols') or 1),
                    did))
                conn.commit()
            except Exception:
                try: conn.rollback()
                except Exception: pass
                conn.execute("""UPDATE devices SET
                    check_group1=?, check_standard=?, check_tolerance=?,
                    check_param1=?, check_param2=?, check_standard2=?, check_tolerance2=?,
                    check_param3=?, check_standard3=?, check_tolerance3=?,
                    check_param4=?, check_standard4=?, check_tolerance4=?,
                    check_param5=?, check_standard5=?, check_tolerance5=?
                    WHERE id=?""", (
                    request.form.get('check_group1') or None,
                    request.form.get('check_standard') or None,
                    request.form.get('check_tolerance') or None,
                    request.form.get('check_param1') or None,
                    request.form.get('check_param2') or None,
                    request.form.get('check_standard2') or None,
                    request.form.get('check_tolerance2') or None,
                    request.form.get('check_param3') or None,
                    request.form.get('check_standard3') or None,
                    request.form.get('check_tolerance3') or None,
                    request.form.get('check_param4') or None,
                    request.form.get('check_standard4') or None,
                    request.form.get('check_tolerance4') or None,
                    request.form.get('check_param5') or None,
                    request.form.get('check_standard5') or None,
                    request.form.get('check_tolerance5') or None,
                    did))
                conn.commit()
            # Зураг тусад нь хадгалах
            for i in ['1','2','3','4','5']:
                try: conn.execute(f"ALTER TABLE devices ADD COLUMN check_photo{i} TEXT")
                except Exception: pass
                f = request.files.get(f'check_photo{i}')
                if f and f.filename:
                    fn = save_file(f, 'devices')
                    if fn:
                        conn.execute(f"UPDATE devices SET check_photo{i}=? WHERE id=?", (fn, did))
                        conn.commit()
            conn.close()
            flash('Шалгалтын тохиргоо хадгалагдлаа!', 'success')
            return redirect(url_for('device_detail', did=did) + '#tab-check')
        photo = save_file(request.files.get('photo'), 'devices')
        pdf   = save_file(request.files.get('passport_pdf'), 'passports')
        mark_id = _resolve_mark(conn,
            request.form.get('manufacturer'),
            request.form.get('model'),
            request.form.get('category'))
        conn.execute("""
            UPDATE devices SET name=?,serial_number=?,mark_id=?,location=?,
            purchase_date=?,warranty_expiry=?,calibration_interval=?,
            status=?,notes=?,lab_id=?,web_link=?,method=?,max_temp=?,particular=?,
            measuring_time=?,measuring_limit=?,dimension=?,capacity=?,weight_kg=?,
            other_spec=?,power=?,frequency=?,voltage=?,specification=?,
            operating_state=?,received_date=?,
            check_standard=?,check_tolerance=?,check_enabled=?,stage=?,check_freq=?
            WHERE id=?
        """, (
            request.form['name'],
            request.form.get('serial_number') or None,
            mark_id,
            request.form.get('location'),
            request.form.get('purchase_date') or None,
            request.form.get('warranty_expiry') or None,
            int(request.form.get('calibration_interval') or 90),
            request.form.get('status','active'),
            request.form.get('notes'),
            request.form.get('lab_id') or None,
            request.form.get('web_link') or None,
            request.form.get('method') or None,
            request.form.get('max_temp') or None,
            request.form.get('particular') or None,
            request.form.get('measuring_time') or None,
            request.form.get('measuring_limit') or None,
            request.form.get('dimension') or None,
            request.form.get('capacity') or None,
            request.form.get('weight_kg') or None,
            request.form.get('other_spec') or None,
            request.form.get('power') or None,
            request.form.get('frequency') or None,
            request.form.get('voltage') or None,
            request.form.get('specification') or None,
            request.form.get('operating_state') or None,
            request.form.get('received_date') or None,
            request.form.get('check_standard') or None,
            request.form.get('check_tolerance') or None,
            1 if request.form.get('check_enabled') else 0,
            request.form.get('stage') or 'both',
            request.form.get('check_freq') or 'daily',
            did
        ))
        if photo: conn.execute("UPDATE devices SET photo=? WHERE id=?", (photo, did))
        if pdf:   conn.execute("UPDATE devices SET passport_pdf=? WHERE id=?", (pdf, did))
        conn.commit(); conn.close()
        flash('Шинэчлэгдлээ!' if lang=='mn' else 'Updated!', 'success')
        return redirect(url_for('device_detail', did=did))
    conn.close()
    return render_template('device/edit.html', device=device, marks=marks, lang=lang)

# ── USAGE ───────────────────────────────────────────────
@app.route('/usage/start/<int:did>', methods=['POST'])
@login_required
def usage_start(did):
    uid  = session.get('user_id', 0)
    conn = get_db()
    if session.get('role') != 'admin':
        perm = conn.execute("SELECT 1 FROM staff_device_permissions WHERE user_id=? AND device_id=?", (uid, did)).fetchone()
        if not perm:
            conn.close(); return jsonify({'error': 'Эрх байхгүй'}), 403
    # Тухайн төхөөрөмж дээр аль хэдийн идэвхтэй сесси байвал давхардуулахгүй
    already = conn.execute("SELECT id FROM usage_logs WHERE user_id=? AND device_id=? AND end_time IS NULL", (uid, did)).fetchone()
    if already:
        conn.close(); return jsonify({'error': 'Та энэ төхөөрөмж дээр аль хэдийн ажиллаж байна!'}), 400
    now = datetime.now().isoformat()
    conn.execute("INSERT INTO usage_logs(device_id,user_id,start_time) VALUES(?,?,?)", (did, uid, now))
    lid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    return jsonify({'success': True, 'log_id': lid, 'start': now[11:16]})

@app.route('/usage/stop/<int:lid>', methods=['POST'])
@login_required
def usage_stop(lid):
    uid  = session.get('user_id', 0)
    conn = get_db()
    log  = conn.execute("SELECT * FROM usage_logs WHERE id=?", (lid,)).fetchone()
    if not log or (log['user_id'] != uid and session.get('role') != 'admin'):
        conn.close(); return jsonify({'error': 'Эрх байхгүй'}), 403
    now  = datetime.now()
    start= datetime.fromisoformat(log['start_time'])
    dur  = round((now - start).total_seconds() / 3600, 2)
    notes= request.json.get('notes','') if request.is_json else ''
    conn.execute("UPDATE usage_logs SET end_time=?,duration_hours=?,notes=? WHERE id=?",
                 (now.isoformat(), dur, notes, lid))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'duration': dur})

# ── CALIBRATION ─────────────────────────────────────────
@app.route('/devices/<int:did>/calibration/add', methods=['POST'])
@login_required
def calibration_add(did):
    lang = session.get('lang','mn')
    conn = get_db()
    doc  = save_file(request.files.get('document'), 'calibrations')
    conn.execute("""
        INSERT INTO calibrations(device_id,performed_by,calibration_date,next_date,result,document,notes)
        VALUES(?,?,?,?,?,?,?)
    """, (did, session['user_id'],
          request.form['calibration_date'],
          request.form.get('next_date') or None,
          request.form.get('result','passed'),
          doc, request.form.get('notes')))
    conn.commit(); conn.close()
    flash('Calibration бүртгэгдлээ!' if lang=='mn' else 'Calibration recorded!', 'success')
    return redirect(url_for('device_detail', did=did))

# ── REPAIR ──────────────────────────────────────────────
@app.route('/devices/<int:did>/repair/add', methods=['POST'])
@login_required
def repair_add(did):
    lang  = session.get('lang','mn')
    conn  = get_db()
    photo = save_file(request.files.get('photo'), 'repairs')
    status= request.form.get('status','new')
    conn.execute("""
        INSERT INTO repairs(device_id,reported_by,reported_date,description,company,repair_date,cost,photo,status,notes)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (did, session['user_id'],
          request.form['reported_date'],
          request.form['description'],
          request.form.get('company'),
          request.form.get('repair_date') or None,
          float(request.form.get('cost') or 0),
          photo, status, request.form.get('notes')))
    if status in ('new', 'repair'):
        conn.execute("UPDATE devices SET status='repair' WHERE id=?", (did,))
    conn.commit(); conn.close()
    flash('Засварын бүртгэл нэмэгдлээ!' if lang=='mn' else 'Repair added!', 'success')
    return redirect(url_for('device_detail', did=did))

# ── INTERNAL DAILY CHECK (жин г.м. дотоод шалгалт) ──────
@app.route('/devices/<int:did>/check/add', methods=['POST'])
@login_required
def device_check_add(did):
    lang = session.get('lang','mn')
    conn = get_db()
    photo = save_file(request.files.get('photo'), 'checks') if request.files.get('photo') else None
    conn.execute("""
        INSERT INTO device_checks(device_id,checked_by,check_date,standard_value,
        measured_value,tolerance,result,standard_value2,measured_value2,tolerance2,
        standard_value3,measured_value3,tolerance3,
        standard_value4,measured_value4,tolerance4,
        standard_value5,measured_value5,tolerance5,notes,photo)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (did, session.get('user_id', 0),
          request.form.get('check_date') or date.today().isoformat(),
          request.form.get('standard_value') or None,
          request.form.get('measured_value') or None,
          request.form.get('tolerance') or None,
          request.form.get('result','pass'),
          request.form.get('standard_value2') or None,
          request.form.get('measured_value2') or None,
          request.form.get('tolerance2') or None,
          request.form.get('standard_value3') or None,
          request.form.get('measured_value3') or None,
          request.form.get('tolerance3') or None,
          request.form.get('standard_value4') or None,
          request.form.get('measured_value4') or None,
          request.form.get('tolerance4') or None,
          request.form.get('standard_value5') or None,
          request.form.get('measured_value5') or None,
          request.form.get('tolerance5') or None,
          request.form.get('notes') or None,
          photo))
    conn.commit(); conn.close()
    flash('Дотоод шалгалт бүртгэгдлээ!' if lang=='mn' else 'Internal check recorded!', 'success')
    return redirect(url_for('device_detail', did=did) + '#tab-check')

@app.route('/devices/check/<int:cid>/delete', methods=['POST'])
@senior_required
def device_check_delete(cid):
    conn = get_db()
    row = conn.execute("SELECT device_id FROM device_checks WHERE id=?", (cid,)).fetchone()
    did = row['device_id'] if row else None
    conn.execute("DELETE FROM device_checks WHERE id=?", (cid,))
    conn.commit(); conn.close()
    if did:
        return redirect(url_for('device_detail', did=did) + '#tab-check')
    return redirect(url_for('devices'))

@app.route('/devices/<int:did>/calib-check', methods=['POST'])
@lab_required
def device_calib_check_add(did):
    lang = session.get('lang','mn')
    conn = get_db()
    check_date = request.form.get('check_date') or date.today().isoformat()
    notes = request.form.get('notes') or None
    pairs = []
    for i in range(1, 6):
        xs = request.form.get(f'x{i}','').strip()
        ys = request.form.get(f'y{i}','').strip()
        if xs and ys:
            try: pairs.append((float(xs), float(ys)))
            except ValueError: pass
    result = 'fail'
    slope_b = intercept_a = r_squared = None
    if len(pairs) >= 2:
        n = len(pairs)
        sx  = sum(p[0] for p in pairs)
        sy  = sum(p[1] for p in pairs)
        sxy = sum(p[0]*p[1] for p in pairs)
        sx2 = sum(p[0]**2 for p in pairs)
        sy2 = sum(p[1]**2 for p in pairs)
        denom = n*sx2 - sx**2
        if denom != 0:
            slope_b = (n*sxy - sx*sy) / denom
            intercept_a = (sy - slope_b*sx) / n
            r_num = (n*sxy - sx*sy)**2
            r_den = denom * (n*sy2 - sy**2)
            r_squared = r_num/r_den if r_den != 0 else None
            if r_squared is not None and r_squared >= 0.999:
                result = 'pass'
    xs = [p[0] for p in pairs] + [None]*(5-len(pairs))
    ys = [p[1] for p in pairs] + [None]*(5-len(pairs))
    try: conn.execute("""
        CREATE TABLE IF NOT EXISTS device_calorimeter_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL REFERENCES devices(id),
            checked_by INTEGER REFERENCES users(id),
            check_date TEXT NOT NULL,
            bomb_no TEXT,
            old_ee REAL,
            new_ee REAL,
            ee_change_pct REAL,
            mass1 REAL, cv1 REAL,
            mass2 REAL, cv2 REAL,
            mass3 REAL, cv3 REAL,
            mass4 REAL, cv4 REAL,
            mass5 REAL, cv5 REAL,
            mass6 REAL, cv6 REAL,
            mass7 REAL, cv7 REAL,
            cv_avg REAL,
            cv_range REAL,
            cv_range_pct REAL,
            cv_rsd REAL,
            n_samples INTEGER,
            result TEXT DEFAULT 'pass',
            ee_warning INTEGER DEFAULT 0,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    except Exception: pass
    try: conn.execute("ALTER TABLE device_calib_checks ADD COLUMN x1 REAL")
    except Exception: pass
    conn.execute("""
        INSERT INTO device_calib_checks
        (device_id,checked_by,check_date,x1,y1,x2,y2,x3,y3,x4,y4,x5,y5,
         slope_b,intercept_a,r_squared,result,notes)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (did, session.get('user_id',0), check_date,
          xs[0],ys[0], xs[1],ys[1], xs[2],ys[2], xs[3],ys[3], xs[4],ys[4],
          slope_b, intercept_a, r_squared, result, notes))
    conn.commit(); conn.close()
    flash('Калибровкийн шалгалт бүртгэгдлээ!', 'success')
    return redirect(url_for('device_detail', did=did) + '#tab-check')

@app.route('/devices/calib-check/<int:cid>/delete', methods=['POST'])
@senior_required
def device_calib_check_delete(cid):
    conn = get_db()
    row = conn.execute("SELECT device_id FROM device_calib_checks WHERE id=?", (cid,)).fetchone()
    did = row['device_id'] if row else None
    conn.execute("DELETE FROM device_calib_checks WHERE id=?", (cid,))
    conn.commit(); conn.close()
    if did:
        return redirect(url_for('device_detail', did=did) + '#tab-check')
    return redirect(url_for('devices'))

@app.route('/devices/<int:did>/calorimeter-check', methods=['POST'])
@lab_required
def device_calorimeter_check_add(did):
    import math
    conn = get_db()
    check_date = request.form.get('check_date') or date.today().isoformat()
    bomb_no    = request.form.get('bomb_no') or None
    notes      = request.form.get('notes') or None
    old_ee = request.form.get('old_ee') or None
    new_ee = request.form.get('new_ee') or None
    try: old_ee = float(old_ee)
    except: old_ee = None
    try: new_ee = float(new_ee)
    except: new_ee = None
    ee_change_pct = None
    ee_warning = 0
    if old_ee and new_ee and old_ee != 0:
        ee_change_pct = abs(new_ee - old_ee) / old_ee * 100
        if ee_change_pct >= 0.2:
            ee_warning = 1
    masses, cvs = [], []
    for i in range(1, 8):
        ms = request.form.get(f'mass{i}','').strip()
        cs = request.form.get(f'cv{i}','').strip()
        if ms and cs:
            try:
                masses.append(float(ms))
                cvs.append(float(cs))
            except ValueError: pass
    cv_avg = cv_range = cv_range_pct = cv_rsd = None
    result = 'fail'
    n = len(cvs)
    if n >= 2:
        cv_avg = sum(cvs) / n
        cv_range = max(cvs) - min(cvs)
        cv_range_pct = cv_range / cv_avg * 100 if cv_avg else None
        variance = sum((v - cv_avg)**2 for v in cvs) / (n - 1)
        cv_rsd = math.sqrt(variance) / cv_avg * 100 if cv_avg else None
        if cv_range_pct is not None and cv_range_pct <= 0.5:
            result = 'pass'
    def _f(lst, i): return lst[i] if i < len(lst) else None
    conn.execute("""
        INSERT INTO device_calorimeter_checks
        (device_id,checked_by,check_date,bomb_no,old_ee,new_ee,ee_change_pct,
         mass1,cv1,mass2,cv2,mass3,cv3,mass4,cv4,mass5,cv5,mass6,cv6,mass7,cv7,
         cv_avg,cv_range,cv_range_pct,cv_rsd,n_samples,result,ee_warning,notes)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (did, session.get('user_id',0), check_date, bomb_no, old_ee, new_ee, ee_change_pct,
          _f(masses,0),_f(cvs,0), _f(masses,1),_f(cvs,1), _f(masses,2),_f(cvs,2),
          _f(masses,3),_f(cvs,3), _f(masses,4),_f(cvs,4), _f(masses,5),_f(cvs,5),
          _f(masses,6),_f(cvs,6),
          cv_avg, cv_range, cv_range_pct, cv_rsd, n, result, ee_warning, notes))
    conn.commit(); conn.close()
    flash('Калориметрийн шалгалт бүртгэгдлээ!', 'success')
    return redirect(url_for('device_detail', did=did) + '#tab-check')

@app.route('/devices/calorimeter-check/<int:cid>/delete', methods=['POST'])
@senior_required
def device_calorimeter_check_delete(cid):
    conn = get_db()
    row = conn.execute("SELECT device_id FROM device_calorimeter_checks WHERE id=?", (cid,)).fetchone()
    did = row['device_id'] if row else None
    conn.execute("DELETE FROM device_calorimeter_checks WHERE id=?", (cid,))
    conn.commit(); conn.close()
    if did:
        return redirect(url_for('device_detail', did=did) + '#tab-check')
    return redirect(url_for('devices'))

# ── НЭГДСЭН ӨДӨР ТУТМЫН БАТАЛГААЖУУЛАЛТ ──────────────────
@app.route('/checks')
@login_required
def checks_page():
    """Бүх тоног төхөөрөмжийн өдөр тутмын баталгаажуулалтыг нэг хуудсанд."""
    lang = session.get('lang','mn')
    sel_date = request.args.get('date') or date.today().isoformat()
    conn = get_db()
    devices = conn.execute("""
        SELECT d.*, dm.manufacturer, dm.model FROM devices d
        LEFT JOIN device_marks dm ON d.mark_id=dm.id
        WHERE COALESCE(d.check_enabled,1)=1 AND d.status NOT IN ('archived','replaced','decommissioned')
        ORDER BY COALESCE(d.check_freq,'daily'), d.name
    """).fetchall()
    # Weekly-д сонгосон өдрийн долоо хоногийн эхний өдрийг тооцно
    from datetime import datetime, timedelta
    sel_dt = datetime.strptime(sel_date, '%Y-%m-%d').date()
    week_start = (sel_dt - timedelta(days=sel_dt.weekday())).isoformat()
    week_end   = (sel_dt + timedelta(days=6 - sel_dt.weekday())).isoformat()
    # Сонгосон өдрийн шалгалтуудыг device_id-аар индекслэх
    rows = conn.execute("""
        SELECT ch.*, u.name as uname FROM device_checks ch
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE ch.check_date=? ORDER BY ch.id DESC
    """, (sel_date,)).fetchall()
    week_rows = conn.execute("""
        SELECT ch.*, u.name as uname FROM device_checks ch
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE ch.check_date BETWEEN ? AND ? ORDER BY ch.check_date DESC, ch.id DESC
    """, (week_start, week_end)).fetchall()
    conn.close()
    today_checks = {}
    for r in rows:
        today_checks.setdefault(r['device_id'], r)
    week_checks = {}
    for r in week_rows:
        week_checks.setdefault(r['device_id'], r)
    return render_template('device/checks.html',
        devices=devices, today_checks=today_checks, week_checks=week_checks,
        sel_date=sel_date, today=date.today().isoformat(),
        week_start=week_start, week_end=week_end, lang=lang)

@app.route('/checks/save', methods=['POST'])
@login_required
def checks_save():
    """Нэг өдрийн бүх төхөөрөмжийн шалгалтыг нэг дор хадгална."""
    lang = session.get('lang','mn')
    if session.get('role') == 'guest':
        return redirect(url_for('checks_page'))
    sel_date = request.form.get('check_date') or date.today().isoformat()
    uid = session.get('user_id', 0)
    conn = get_db()
    saved = 0
    for did in request.form.getlist('device_id'):
        measured = (request.form.get(f'measured_{did}') or '').strip()
        if not measured:
            continue  # хэмжсэн утга оруулаагүй бол алгасна
        # Тухайн өдрийн хуучин бичлэгийг устгаад шинээр бичих (давхардахгүй)
        conn.execute("DELETE FROM device_checks WHERE device_id=? AND check_date=?", (did, sel_date))
        cal_adj = 1 if request.form.get(f'cal_adj_{did}') else 0
        conn.execute("""
            INSERT INTO device_checks(device_id,checked_by,check_date,standard_value,
            measured_value,tolerance,result,calibration_adjusted,
            standard_value2,measured_value2,tolerance2,
            standard_value3,measured_value3,tolerance3,
            standard_value4,measured_value4,tolerance4,
            standard_value5,measured_value5,tolerance5,notes)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (did, uid, sel_date,
              request.form.get(f'standard_{did}') or None,
              measured,
              request.form.get(f'tolerance_{did}') or None,
              request.form.get(f'result_{did}','pass'),
              cal_adj,
              request.form.get(f'standard2_{did}') or None,
              request.form.get(f'measured2_{did}') or None,
              request.form.get(f'tolerance2_{did}') or None,
              request.form.get(f'standard3_{did}') or None,
              request.form.get(f'measured3_{did}') or None,
              request.form.get(f'tolerance3_{did}') or None,
              request.form.get(f'standard4_{did}') or None,
              request.form.get(f'measured4_{did}') or None,
              request.form.get(f'tolerance4_{did}') or None,
              request.form.get(f'standard5_{did}') or None,
              request.form.get(f'measured5_{did}') or None,
              request.form.get(f'tolerance5_{did}') or None,
              request.form.get(f'notes_{did}') or None))
        saved += 1
    conn.commit(); conn.close()
    flash(f'{saved} төхөөрөмжийн баталгаажуулалт хадгалагдлаа!', 'success')
    return redirect(url_for('checks_page', date=sel_date))

@app.route('/checks/monthly')
@login_required
def checks_monthly():
    """Сарын харагдац — бүх жингийн шалгалтыг нэг хүснэгтэд (Excel Sheet 1 загвараар)."""
    import calendar as cal_mod
    lang = session.get('lang', 'mn')
    today = date.today()
    year  = int(request.args.get('year',  today.year))
    month = int(request.args.get('month', today.month))
    _, days_in_month = cal_mod.monthrange(year, month)
    d_from = f"{year}-{month:02d}-01"
    d_to   = f"{year}-{month:02d}-{days_in_month:02d}"
    conn = get_db()
    devices = conn.execute("""
        SELECT d.*, dm.manufacturer, dm.model FROM devices d
        LEFT JOIN device_marks dm ON d.mark_id=dm.id
        WHERE COALESCE(d.check_enabled,1)=1
          AND d.status NOT IN ('archived','replaced','decommissioned')
        ORDER BY COALESCE(d.check_freq,'daily'), d.name
    """).fetchall()
    rows = conn.execute("""
        SELECT ch.*, u.name as uname FROM device_checks ch
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE ch.check_date BETWEEN ? AND ?
    """, (d_from, d_to)).fetchall()
    conn.close()
    # (device_id, day) → check record
    grid = {}
    for r in rows:
        day = int(r['check_date'].split('-')[2])
        grid[(r['device_id'], day)] = r
    return render_template('device/checks_monthly.html',
        devices=devices, grid=grid,
        year=year, month=month, days_in_month=days_in_month,
        today=today, lang=lang)

@app.route('/checks/export')
@login_required
def checks_export():
    """Баталгаажуулалтын бүртгэлийг Excel болгон татах."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    d_from = request.args.get('from') or date.today().replace(day=1).isoformat()
    d_to   = request.args.get('to') or date.today().isoformat()
    conn = get_db()
    rows = conn.execute("""
        SELECT ch.check_date, d.name as device_name, d.lab_id,
               ch.standard_value, ch.measured_value, ch.tolerance,
               ch.result, ch.calibration_adjusted, ch.notes, u.name as uname
        FROM device_checks ch
        LEFT JOIN devices d ON d.id=ch.device_id
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE ch.check_date BETWEEN ? AND ?
        ORDER BY ch.check_date DESC, d.name
    """, (d_from, d_to)).fetchall()
    conn.close()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Баталгаажуулалт'
    headers = ['Огноо','Төхөөрөмж','Лаб дугаар','Стандарт','Хэмжсэн','Зөвшөөрөх зөрүү','Үр дүн','Тохируулга','Шалгасан','Тэмдэглэл']
    ws.append(headers)
    hf = Font(bold=True, color='FFFFFF')
    fill = PatternFill('solid', fgColor='1A2744')
    for c in ws[1]:
        c.font = hf; c.fill = fill; c.alignment = Alignment(horizontal='center')
    for r in rows:
        ws.append([r['check_date'], r['device_name'], r['lab_id'] or '',
                   r['standard_value'] or '', r['measured_value'] or '',
                   r['tolerance'] or '',
                   'Тэнцсэн' if r['result']=='pass' else 'Тэнцээгүй',
                   'Тийм' if r['calibration_adjusted'] else '',
                   r['uname'] or '', r['notes'] or ''])
    widths = [12, 24, 12, 14, 14, 16, 12, 10, 18, 24]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = w
    buf = io.BytesIO()
    wb.save(buf); buf.seek(0)
    fname = f'baталгаажуулалт_{d_from}_{d_to}.xlsx'
    return send_file(buf, as_attachment=True, download_name=fname,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/repair/<int:rid>/close', methods=['POST'])
@login_required
def repair_close(rid):
    conn = get_db()
    rep  = conn.execute("SELECT * FROM repairs WHERE id=?", (rid,)).fetchone()
    if rep:
        conn.execute("UPDATE repairs SET status='done' WHERE id=?", (rid,))
        conn.execute("UPDATE devices SET status='active' WHERE id=?", (rep['device_id'],))
        conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── STAFF ───────────────────────────────────────────────
@app.route('/staff')
@login_required
def staff_list():
    lang = session.get('lang','mn')
    conn = get_db()
    is_admin = session.get('role') == 'admin'
    role_filter = '' if is_admin else "AND role != 'admin'"
    users_a = conn.execute(f"""
        SELECT * FROM users WHERE is_active=1 AND shift='A' {role_filter}
        ORDER BY CASE role
            WHEN 'admin' THEN 1 WHEN 'senior' THEN 2 WHEN 'staff' THEN 3
            WHEN 'preparer' THEN 4 WHEN 'geologist' THEN 5 ELSE 6 END, name
    """).fetchall()
    users_b = conn.execute(f"""
        SELECT * FROM users WHERE is_active=1 AND shift='B' {role_filter}
        ORDER BY CASE role
            WHEN 'admin' THEN 1 WHEN 'senior' THEN 2 WHEN 'staff' THEN 3
            WHEN 'preparer' THEN 4 WHEN 'geologist' THEN 5 ELSE 6 END, name
    """).fetchall()
    users_none = conn.execute(f"""
        SELECT * FROM users WHERE is_active=1 AND (shift IS NULL OR shift='') {role_filter}
        ORDER BY CASE role
            WHEN 'admin' THEN 1 WHEN 'senior' THEN 2 WHEN 'staff' THEN 3
            WHEN 'preparer' THEN 4 WHEN 'geologist' THEN 5 ELSE 6 END, name
    """).fetchall()
    _bayj_raw = conn.execute("SELECT * FROM users WHERE is_active=1 AND role='bayjuulach'").fetchall()
    _pos_rank = ['Үйлдвэрийн дарга','Ашиглалтын ахлах инженер','Ашиглалтын инженер',
                 'Цахилгаан автоматжуулалтын инженер','Удирдлагын оператор',
                 'Орчуулагч, бичиг хэргийн мэргэжилтэн']
    bayj_users = sorted(_bayj_raw, key=lambda u: (
        _pos_rank.index(u['position'].strip()) if u['position'] and u['position'].strip() in _pos_rank else 99,
        u['name']
    ))
    conn.close()
    return render_template('admin/staff_list.html', users_a=users_a, users_b=users_b, users_none=users_none, bayj_users=bayj_users, lang=lang)

@app.route('/staff/add', methods=['GET','POST'])
@senior_required
def staff_add():
    lang    = session.get('lang','mn')
    conn    = get_db()
    devices = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
    if request.method == 'POST':
        existing = conn.execute("SELECT id FROM users WHERE employee_id=?", (request.form['employee_id'],)).fetchone()
        if existing:
            conn.close()
            flash(f"'{request.form['employee_id']}' ID аль хэдийн бүртгэлтэй байна!", 'error')
            devices2 = get_db().execute("SELECT * FROM devices ORDER BY name").fetchall()
            return render_template('admin/staff_add.html', devices=devices2, lang=lang)
        try:
            photo = save_file(request.files.get('photo'), 'staff')
            pw    = hash_password(request.form['password'])
            # Senior бол зөвхөн 'staff' эрх өгч болно
            role_to_set = request.form.get('role','staff')
            if session.get('role') == 'senior' and role_to_set in ('admin','senior'):
                role_to_set = 'staff'
            is_bayj = role_to_set == 'bayjuulach'
            can_reg = 1 if (is_bayj and request.form.get('can_register')) else 0
            can_view = 1 if (is_bayj and request.form.get('can_view_result')) else 0
            conn.execute("""
                INSERT INTO users(employee_id,name,position,phone,email,photo,role,password_hash,joined_date,shift,can_register,can_view_result)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                request.form['employee_id'], request.form['name'],
                request.form.get('position'), request.form.get('phone'),
                request.form.get('email'), photo,
                role_to_set, pw,
                request.form.get('joined_date') or None,
                request.form.get('shift') or None,
                can_reg, can_view
            ))
            uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            # Геологичид (харилцагч) тоног ашиглах эрх олгохгүй
            if role_to_set != 'geologist':
                for did in request.form.getlist('device_permissions'):
                    conn.execute("INSERT OR IGNORE INTO staff_device_permissions(user_id,device_id) VALUES(?,?)", (uid, did))
            conn.commit(); conn.close()
            flash('Ажилтан нэмэгдлээ!' if lang=='mn' else 'Staff added!', 'success')
            return redirect(url_for('staff_list'))
        except Exception as e:
            conn.close()
            flash(f'Алдаа: {str(e)}', 'error')
            devices2 = get_db().execute("SELECT * FROM devices ORDER BY name").fetchall()
            return render_template('admin/staff_add.html', devices=devices2, lang=lang)
    conn.close()
    return render_template('admin/staff_add.html', devices=devices, lang=lang)


@app.route('/staff/<int:uid>')
@login_required
def staff_detail(uid):
    if session.get('role') not in ('admin','senior','guest') and session.get('user_id') != uid:
        return redirect(url_for('dashboard'))
    lang = session.get('lang','mn')
    conn = get_db()
    target  = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        conn.close()
        return redirect(url_for('staff_list'))

    # ── ХАРИЛЦАГЧ (геологи + баяжуулах): зөвхөн дээж бүртгэлийн мэдээлэл ──
    if target['role'] in ('geologist', 'bayjuulach'):
        geo_total = conn.execute("SELECT COUNT(*) FROM geo_samples WHERE registered_by=?", (uid,)).fetchone()[0]
        geo_done  = conn.execute("SELECT COUNT(*) FROM geo_samples WHERE registered_by=? AND status='done'", (uid,)).fetchone()[0]
        geo_active = geo_total - geo_done
        geo_by_type = conn.execute("""
            SELECT sample_type, COUNT(*) as cnt FROM geo_samples
            WHERE registered_by=? GROUP BY sample_type ORDER BY cnt DESC
        """, (uid,)).fetchall()
        geo_recent = conn.execute("""
            SELECT g.*, sr.lab_number FROM geo_samples g
            LEFT JOIN sample_receipt sr ON sr.geo_sample_id=g.id
            WHERE g.registered_by=? ORDER BY g.created_at DESC LIMIT 30
        """, (uid,)).fetchall()
        geo_monthly = conn.execute("""
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
            FROM geo_samples WHERE registered_by=?
            GROUP BY month ORDER BY month
        """, (uid,)).fetchall()
        # Үр дүн харсан лог (геологи + баяжуулах)
        view_total = conn.execute("SELECT COUNT(*) FROM result_view_log WHERE user_id=?", (uid,)).fetchone()[0]
        view_log = conn.execute("""
            SELECT vl.viewed_at, sr.lab_number, g.sample_name
            FROM result_view_log vl
            JOIN sample_receipt sr ON sr.id=vl.receipt_id
            JOIN geo_samples g ON g.id=sr.geo_sample_id
            WHERE vl.user_id=? ORDER BY vl.viewed_at DESC LIMIT 20
        """, (uid,)).fetchall()
        conn.close()
        return render_template('staff/detail_geologist.html', target=target, lang=lang,
                               geo_total=geo_total, geo_done=geo_done, geo_active=geo_active,
                               geo_by_type=geo_by_type, geo_recent=geo_recent, geo_monthly=geo_monthly,
                               view_total=view_total, view_log=view_log)

    logs    = conn.execute("""
        SELECT ul.*, d.name as dname FROM usage_logs ul
        LEFT JOIN devices d ON d.id=ul.device_id
        WHERE ul.user_id=? ORDER BY ul.start_time DESC LIMIT 50
    """, (uid,)).fetchall()
    my_devs = conn.execute("""
        SELECT d.* FROM devices d
        JOIN staff_device_permissions p ON p.device_id=d.id
        WHERE p.user_id=?
    """, (uid,)).fetchall()
    device_usage = conn.execute("""
        SELECT d.id as device_id, d.name as device_name,
               COUNT(*) as sessions,
               COALESCE(SUM(CAST((julianday(ul.end_time)-julianday(ul.start_time))*1440 AS INTEGER)),0) as total_min,
               MAX(ul.start_time) as last_used
        FROM usage_logs ul
        JOIN devices d ON d.id=ul.device_id
        WHERE ul.user_id=? AND ul.end_time IS NOT NULL
        GROUP BY d.id ORDER BY total_min DESC
    """, (uid,)).fetchall()
    # Stats
    total_done     = conn.execute("SELECT COUNT(*) FROM sample_entries WHERE done_by=? AND row_status IN ('done','approved')", (uid,)).fetchone()[0]
    total_approved = conn.execute("SELECT COUNT(*) FROM sample_entries WHERE approved_by=? AND row_status='approved'", (uid,)).fetchone()[0]
    total_hours    = conn.execute("SELECT COALESCE(SUM(duration_hours),0) FROM usage_logs WHERE user_id=? AND end_time IS NOT NULL", (uid,)).fetchone()[0]
    # QC radar
    qc_rows = conn.execute("""
        SELECT qs.parameter,
               SUM(CASE WHEN ABS(e.mad - e2.mad) <= qs.tolerance THEN 1 ELSE 0 END)*1.0/COUNT(*)*100 as pct
        FROM sample_entries e
        JOIN sample_entries e2 ON e2.receipt_id=e.receipt_id AND e2.row_num=e.row_num AND e2.is_duplicate=1
        JOIN qc_settings qs ON qs.parameter='Mad'
        WHERE e.is_duplicate=0 AND e.done_by=? AND e.mad IS NOT NULL AND e2.mad IS NOT NULL
        LIMIT 1
    """, (uid,)).fetchall()
    qc_radar = {}
    # Monthly analysis counts
    now = datetime.now()
    def monthly_counts(months_back):
        rows = conn.execute("""
            SELECT strftime('%Y-%m', se.done_at) as month, COUNT(*) as cnt
            FROM sample_entries se
            WHERE se.done_by=? AND se.row_status IN ('done','approved')
              AND se.done_at >= date('now', ?)
            GROUP BY month ORDER BY month
        """, (uid, f'-{months_back} months')).fetchall()
        return rows
    monthly_6   = monthly_counts(6)
    monthly_12  = monthly_counts(12)
    monthly_all = conn.execute("""
        SELECT strftime('%Y-%m', done_at) as month, COUNT(*) as cnt
        FROM sample_entries WHERE done_by=? AND row_status IN ('done','approved')
        GROUP BY month ORDER BY month
    """, (uid,)).fetchall()
    conn.close()
    return render_template('staff/detail.html', target=target, logs=logs, my_devices=my_devs,
                           device_usage=device_usage, lang=lang,
                           total_done=total_done, total_approved=total_approved, total_hours=total_hours,
                           qc_radar=qc_radar, monthly_6=monthly_6, monthly_12=monthly_12, monthly_all=monthly_all)

# ── INTERNAL QC ─────────────────────────────────────────
@app.route('/internal-qc')
@lab_required
def internal_qc_list():
    conn = get_db()
    rows = conn.execute("""
        SELECT iq.*,
            u.name as assigned_name,
            sr1.lab_number as lab1, g1.sample_name as sname1,
            sr2.lab_number as lab2, g2.sample_name as sname2
        FROM internal_qc iq
        LEFT JOIN users u ON u.id=iq.assigned_to
        LEFT JOIN sample_receipt sr1 ON sr1.id=iq.receipt_id_1
        LEFT JOIN geo_samples g1 ON g1.id=sr1.geo_sample_id
        LEFT JOIN sample_receipt sr2 ON sr2.id=iq.receipt_id_2
        LEFT JOIN geo_samples g2 ON g2.id=sr2.geo_sample_id
        ORDER BY iq.created_at DESC
    """).fetchall()
    conn.close()
    return render_template('analysis/internal_qc.html', rows=rows, lang=session.get('lang','mn'), role=session.get('role'))

@app.route('/internal-qc/create', methods=['POST'])
@senior_required
def internal_qc_create():
    import random
    conn = get_db()
    from datetime import datetime, timedelta
    d_to = datetime.now().strftime('%Y-%m-%d')
    d_from = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    candidates = conn.execute("""
        SELECT DISTINCT sr.id FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        JOIN sample_entries se ON se.receipt_id=sr.id
        WHERE g.sample_type IN ('PIT','STOCKPILE','EXPORT','CONTROL')
        AND se.is_duplicate=0
        AND se.row_status IN ('done','approved')
        AND sr.received_date BETWEEN ? AND ?
    """, (d_from, d_to)).fetchall()
    if len(candidates) < 1:
        conn.close()
        flash('Өмнөх 7 хоногт давтан шинжлэх хангалттай дээж байхгүй байна', 'error')
        return redirect(url_for('analysis'))
    picked = random.sample([r['id'] for r in candidates], 1)
    def pick_row(rid):
        rows = conn.execute(
            "SELECT row_num FROM sample_entries WHERE receipt_id=? AND is_duplicate=0 AND row_status IN ('done','approved')",
            (rid,)).fetchall()
        if not rows: return 1
        return random.choice([r['row_num'] for r in rows])
    rn1 = pick_row(picked[0])
    assigned = request.form.get('assigned_to') or session['user_id']
    last = conn.execute("SELECT qc_number FROM internal_qc WHERE qc_number LIKE 'QC%' ORDER BY id DESC LIMIT 1").fetchone()
    if last and last['qc_number'] and last['qc_number'][2:].isdigit():
        seq = int(last['qc_number'][2:]) + 1
    else:
        seq = 1
    qc_number = f'QC{seq:03d}'
    cur = conn.execute("""INSERT INTO internal_qc (qc_number, triggered_date, receipt_id_1, receipt_id_2, row_num_1, row_num_2, assigned_to, created_by)
        VALUES (?,?,?,NULL,?,NULL,?,?)""", (qc_number, d_to, picked[0], rn1, assigned, session['user_id']))
    qc_id = cur.lastrowid
    conn.commit()
    conn.close()
    flash('Дотоод QC үүслээ — доорх жагсаалтаас сонгож шинжилгээ хийнэ үү', 'success')
    return redirect(url_for('analysis'))

@app.route('/internal-qc/<int:qc_id>/measure')
@lab_required
def internal_qc_measure(qc_id):
    conn = get_db()
    qc = conn.execute("""
        SELECT iq.*,
            sr1.lab_number as lab1, g1.sample_name as sname1,
            sr2.lab_number as lab2, g2.sample_name as sname2
        FROM internal_qc iq
        LEFT JOIN sample_receipt sr1 ON sr1.id=iq.receipt_id_1
        LEFT JOIN geo_samples g1 ON g1.id=sr1.geo_sample_id
        LEFT JOIN sample_receipt sr2 ON sr2.id=iq.receipt_id_2
        LEFT JOIN geo_samples g2 ON g2.id=sr2.geo_sample_id
        WHERE iq.id=?
    """, (qc_id,)).fetchone()
    if not qc:
        conn.close()
        flash('Бүртгэл олдсонгүй', 'error')
        return redirect(url_for('internal_qc_list'))
    PARAMS = ['adb','vdb','fcdb','sdb','qdb','fsi','g_index']
    DB_LABELS = {'adb':'Adb','vdb':'Vdb','fcdb':'FCdb','sdb':'Sdb','qdb':'Qgr,db','fsi':'CSN','g_index':'G-index'}
    DB_UNITS  = {'adb':'%','vdb':'%','fcdb':'%','sdb':'%','qdb':'ккал/кг','fsi':'','g_index':''}
    def ad_to_db(ed):
        mad = ed.get('mad') or 0
        f = 100 / (100 - mad) if mad < 100 else 1
        result = {}
        try:
            if ed.get('aad') is not None: result['adb'] = round(ed['aad'] * f, 2)
            if ed.get('vad') is not None: result['vdb'] = round(ed['vad'] * f, 2)
            if ed.get('fc')  is not None: result['fcdb']= round(ed['fc']  * f, 2)
            if ed.get('sulfur') is not None: result['sdb'] = round(ed['sulfur'] * f, 2)
            if ed.get('cal_value') is not None: result['qdb'] = round(ed['cal_value'] / 4.1868 * f, 0)
            if ed.get('fsi') is not None: result['fsi'] = ed['fsi']
            if ed.get('g_val') is not None: result['g_index'] = ed['g_val']
        except: pass
        return result
    def get_orig(rid, row_num=None):
        if not rid: return {}
        if row_num:
            e = conn.execute("SELECT * FROM sample_entries WHERE receipt_id=? AND row_num=? AND is_duplicate=0", (rid, row_num)).fetchone()
        else:
            e = conn.execute("SELECT * FROM sample_entries WHERE receipt_id=? AND is_duplicate=0 AND row_status IN ('done','approved') ORDER BY row_num LIMIT 1", (rid,)).fetchone()
        if not e: return {}
        ed = dict(e)
        try:
            if ed.get('mad') is None and ed.get('dc_sample') and ed['dc_sample'] > 0:
                ed['mad'] = (ed['dc_tare'] + ed['dc_sample'] - ed['dc_dried']) / ed['dc_sample'] * 100
            if ed.get('aad') is None and ed.get('ash_sample') and ed['ash_sample'] > 0:
                ed['aad'] = (ed['ash_burned'] - ed['ash_tare']) / ed['ash_sample'] * 100
            if ed.get('vad') is None and ed.get('vol_sample') and ed['vol_sample'] > 0 and ed.get('mad') is not None:
                ed['vad'] = (ed['vol_tare'] + ed['vol_sample'] - ed['vol_burned']) / ed['vol_sample'] * 100 - ed['mad']
            if ed.get('fc') is None and all(ed.get(x) is not None for x in ['mad','aad','vad']):
                ed['fc'] = 100 - ed['mad'] - ed['aad'] - ed['vad']
        except: pass
        return ad_to_db(ed)
    orig1 = get_orig(qc['receipt_id_1'], qc['row_num_1'])
    orig2 = get_orig(qc['receipt_id_2'], qc['row_num_2'])
    results = conn.execute("SELECT * FROM internal_qc_results WHERE qc_id=?", (qc_id,)).fetchall()
    qc_tol = {r['parameter']: r['tolerance'] for r in conn.execute("SELECT parameter, tolerance FROM qc_settings").fetchall()}
    conn.close()
    db_to_tol = {'adb':'Aad','vdb':'Vad','fcdb':'Fc','sdb':'Stad','qdb':'Qb_ad','fsi':'FSI','g_index':'G_index'}
    return render_template('analysis/internal_qc_measure.html',
        qc=qc, orig1=orig1, orig2=orig2, results=results,
        qc_tol=qc_tol, params=PARAMS, db_labels=DB_LABELS, db_units=DB_UNITS,
        db_to_tol=db_to_tol,
        lang=session.get('lang','mn'), role=session.get('role'))

@app.route('/internal-qc/<int:qc_id>/approve')
@senior_required
def internal_qc_approve(qc_id):
    conn = get_db()
    conn.execute("UPDATE internal_qc SET status='done' WHERE id=? AND status='pending'", (qc_id,))
    conn.commit()
    conn.close()
    flash('QC баталгаажлаа!', 'success')
    return redirect(url_for('archive'))

@app.route('/internal-qc/<int:qc_id>/done', methods=['POST'])
@lab_required
def internal_qc_done(qc_id):
    conn = get_db()
    notes = request.form.get('notes','')
    conn.execute("DELETE FROM internal_qc_results WHERE qc_id=?", (qc_id,))
    params = ['adb','vdb','fcdb','sdb','qdb','fsi','g_index']
    db_to_tol = {'adb':'Aad','vdb':'Vad','fcdb':'Fc','sdb':'Stad','qdb':'Qb_ad','fsi':'FSI','g_index':'G_index'}
    for receipt_id in [request.form.get('rid1'), request.form.get('rid2')]:
        if not receipt_id: continue
        for p in params:
            rep = request.form.get(f'rep_{receipt_id}_{p}')
            orig = request.form.get(f'orig_{receipt_id}_{p}')
            if rep and orig:
                try:
                    o,r = float(orig), float(rep)
                    diff = abs(o-r)
                    tol_key = db_to_tol.get(p, p.capitalize())
                    tol = conn.execute("SELECT tolerance FROM qc_settings WHERE parameter=?", (tol_key,)).fetchone()
                    within = 1 if (tol and diff <= float(tol['tolerance'])) else 0
                    conn.execute("""INSERT INTO internal_qc_results (qc_id,receipt_id,parameter,original_value,repeat_value,difference,within_tolerance)
                        VALUES (?,?,?,?,?,?,?)""", (qc_id, int(receipt_id), p, o, r, diff, within))
                except: pass
    conn.execute("UPDATE internal_qc SET status='done', notes=? WHERE id=?", (notes, qc_id))
    conn.commit()
    conn.close()
    flash('Дотоод QC бүртгэгдлээ', 'success')
    return redirect(url_for('internal_qc_list'))

# ── ARCHIVE ─────────────────────────────────────────────
@app.route('/archive')
@login_required
def archive():
    lang = session.get('lang','mn')
    conn = get_db()
    archived_devices = conn.execute("""
        SELECT d.*, dm.manufacturer, dm.model FROM devices d
        LEFT JOIN device_marks dm ON d.mark_id=dm.id
        WHERE d.status IN ('archived','replaced','decommissioned')
        ORDER BY d.name
    """).fetchall()
    archived_staff = conn.execute(
        "SELECT * FROM users WHERE is_active=0 AND role != 'admin' ORDER BY name"
    ).fetchall()
    completed_repairs = conn.execute("""
        SELECT r.*, d.name as dname FROM repairs r
        LEFT JOIN devices d ON d.id=r.device_id
        WHERE r.status IN ('done','replaced')
        ORDER BY r.reported_date DESC
    """).fetchall()
    completed_samples = conn.execute("""
        SELECT g.*, sr.lab_number, sr.lab_serial, sr.id as receipt_id,
               u.name as reg_name
        FROM geo_samples g
        JOIN sample_receipt sr ON sr.geo_sample_id=g.id
        LEFT JOIN users u ON u.id=g.registered_by
        WHERE g.status='done'
        ORDER BY sr.lab_serial DESC LIMIT 200
    """).fetchall()
    if session.get('role') == 'bayjuulach':
        u = conn.execute("SELECT can_view_result FROM users WHERE id=?", (session.get('user_id'),)).fetchone()
        if not u or not u['can_view_result']:
            completed_samples = []
        else:
            completed_samples = [s for s in completed_samples if 6000 <= (s['lab_serial'] or 0) <= 6999]
    done_qc = conn.execute("""
        SELECT iq.*, sr1.lab_number as lab1, g1.sample_name as sname1,
               u.name as assigned_name
        FROM internal_qc iq
        LEFT JOIN sample_receipt sr1 ON sr1.id=iq.receipt_id_1
        LEFT JOIN geo_samples g1 ON g1.id=sr1.geo_sample_id
        LEFT JOIN users u ON u.id=iq.assigned_to
        WHERE iq.status='done'
        ORDER BY iq.triggered_date DESC LIMIT 200
    """).fetchall()
    conn.close()
    return render_template('admin/archive.html',
        archived_devices=archived_devices,
        archived_staff=archived_staff,
        completed_repairs=completed_repairs,
        done_samples=completed_samples,
        done_qc=done_qc,
        lang=lang)

@app.route('/archive/result/<int:receipt_id>')
@login_required
def archive_result(receipt_id):
    lang = session.get('lang','mn')
    role = session.get('role','')
    conn = get_db()
    receipt = conn.execute("""
        SELECT sr.*, g.sample_name, g.sample_type, g.location,
               g.collected_date, g.quantity,
               ug.name as geo_name, up.name as prep_name
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        LEFT JOIN users ug ON ug.id=g.registered_by
        LEFT JOIN users up ON up.id=sr.received_by
        WHERE sr.id=?
    """, (receipt_id,)).fetchone()
    if not receipt:
        conn.close()
        flash('Бүртгэл олдсонгүй', 'error')
        return redirect(url_for('archive'))
    entries = conn.execute("""
        SELECT se.*, u1.name as done_name, u2.name as approved_name
        FROM sample_entries se
        LEFT JOIN users u1 ON u1.id=se.done_by
        LEFT JOIN users u2 ON u2.id=se.approved_by
        WHERE se.receipt_id=?
        ORDER BY se.row_num, se.is_duplicate
    """, (receipt_id,)).fetchall()
    qc = {r['parameter']: r for r in conn.execute("SELECT * FROM qc_settings").fetchall()}
    conn.close()
    return render_template('analysis/archive_result.html',
        receipt=receipt, entries=entries, qc=qc, lang=lang, role=role)

@app.route('/archive/measure/<int:receipt_id>')
@login_required
def archive_measure(receipt_id):
    lang = session.get('lang','mn')
    conn = get_db()
    receipt = conn.execute("""
        SELECT sr.*, g.sample_name, g.sample_type, g.location, g.quantity
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        WHERE sr.id=?
    """, (receipt_id,)).fetchone()
    if not receipt:
        conn.close()
        flash('Бүртгэл олдсонгүй', 'error')
        return redirect(url_for('archive'))
    entries = conn.execute("""
        SELECT * FROM sample_entries WHERE receipt_id=?
        ORDER BY row_num, is_duplicate
    """, (receipt_id,)).fetchall()
    conn.close()
    return render_template('analysis/archive_measure.html',
        receipt=receipt, entries=entries, lang=lang)

@app.route('/analysis/find-receipt')
@admin_required
def analysis_find_receipt():
    lab_number = request.args.get('lab_number','').strip()
    conn = get_db()
    row = conn.execute("""
        SELECT sr.id, sr.lab_number, sr.received_date, g.quantity, g.sample_name
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        WHERE sr.lab_number=?
    """, (lab_number,)).fetchone()
    conn.close()
    if row:
        return jsonify({
            'id': row['id'],
            'lab_number': row['lab_number'],
            'received_date': row['received_date'] or '',
            'quantity': row['quantity'] or 0,
            'sample_name': row['sample_name'] or ''
        })
    return jsonify({})

@app.route('/analysis/delete/<int:receipt_id>', methods=['POST'])
@admin_required
def analysis_delete(receipt_id):
    conn = get_db()
    receipt = conn.execute('SELECT geo_sample_id FROM sample_receipt WHERE id=?', (receipt_id,)).fetchone()
    if receipt:
        conn.execute('DELETE FROM sample_entries WHERE receipt_id=?', (receipt_id,))
        conn.execute('DELETE FROM sample_receipt WHERE id=?', (receipt_id,))
        conn.execute("UPDATE geo_samples SET status='pending' WHERE id=?", (receipt['geo_sample_id'],))
        conn.commit()
        flash('Шинжилгээний бүртгэл устгагдлаа', 'success')
    conn.close()
    return redirect(url_for('analysis'))

@app.route('/archive/reopen/<int:receipt_id>', methods=['POST'])
@senior_required
def archive_reopen(receipt_id):
    conn = get_db()
    receipt = conn.execute('SELECT geo_sample_id FROM sample_receipt WHERE id=?', (receipt_id,)).fetchone()
    if receipt:
        conn.execute("UPDATE geo_samples SET status='analysing' WHERE id=?", (receipt['geo_sample_id'],))
        conn.execute("UPDATE sample_receipt SET prep_status='ready' WHERE id=?", (receipt_id,))
        conn.execute("UPDATE sample_entries SET row_status='done', approved_by=NULL, approved_at=NULL WHERE receipt_id=? AND row_status='approved'", (receipt_id,))
        conn.commit()
        flash('Шинжилгээ дахин нээгдлээ', 'success')
    conn.close()
    return redirect(url_for('analysis_result', receipt_id=receipt_id))

@app.route('/archive/delete/<int:receipt_id>', methods=['POST'])
@admin_required
def archive_delete(receipt_id):
    conn = get_db()
    try:
        receipt = conn.execute('SELECT geo_sample_id FROM sample_receipt WHERE id=?', (receipt_id,)).fetchone()
        if receipt:
            geo_id = receipt['geo_sample_id']
            # QC байгаа эсэх шалгах — байвал устгахгүй анхааруулна
            qc_linked = conn.execute(
                "SELECT COUNT(*) FROM internal_qc WHERE receipt_id_1=? OR receipt_id_2=?",
                (receipt_id, receipt_id)
            ).fetchone()[0]
            if qc_linked:
                conn.close()
                flash(f'Энэ дээжтэй {qc_linked} QC бүртгэл холбоотой байна. Эхлээд QC-г устгана уу.', 'error')
                return redirect(url_for('archive'))
            # Хамааралтай бүх бичлэгийг эхлээд устгана (child → parent дараалал)
            conn.execute("DELETE FROM result_view_log WHERE receipt_id=?", (receipt_id,))
            conn.execute("DELETE FROM device_usage_log WHERE receipt_id=?", (receipt_id,))
            conn.execute("DELETE FROM sample_entries WHERE receipt_id=?", (receipt_id,))
            conn.execute("DELETE FROM sample_receipt WHERE id=?", (receipt_id,))
            conn.execute("DELETE FROM geo_samples WHERE id=?", (geo_id,))
        conn.commit()
        flash('Бүртгэл бүрмөсөн устгагдлаа.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Устгахад алдаа гарлаа: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('archive'))

@app.route('/archive/qc-delete/<int:qc_id>', methods=['POST'])
@admin_required
def archive_qc_delete(qc_id):
    conn = get_db()
    conn.execute("DELETE FROM internal_qc_results WHERE qc_id=?", (qc_id,))
    conn.execute("DELETE FROM internal_qc WHERE id=?", (qc_id,))
    conn.commit()
    conn.close()
    flash('QC бүртгэл бүрмөсөн устгагдлаа.', 'success')
    return redirect(url_for('archive'))

@app.route('/archive/export/<int:receipt_id>')
@login_required
def analysis_export_report(receipt_id):
    return redirect(url_for('analysis_export', receipt_id=receipt_id))

# ── STAFF EDIT (admin/senior) ───────────────────────────
@app.route('/staff/<int:uid>/edit', methods=['GET','POST'])
@senior_required
def staff_edit(uid):
    lang = session.get('lang','mn')
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    devices = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
    perms = [r['device_id'] for r in conn.execute("SELECT device_id FROM staff_device_permissions WHERE user_id=?", (uid,)).fetchall()]
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_info':
            photo = save_file(request.files.get('photo'), 'staff')
            # Senior зөвхөн staff эрх өгч болно
            role_to_set = request.form.get('role', target['role'])
            if session.get('role') == 'senior' and role_to_set in ('admin','senior'):
                role_to_set = target['role']
            is_bayj = role_to_set == 'bayjuulach'
            can_reg  = 1 if (is_bayj and request.form.get('can_register')) else 0
            can_view = 1 if (is_bayj and request.form.get('can_view_result')) else 0
            conn.execute("""
                UPDATE users SET name=?,position=?,phone=?,email=?,role=?,joined_date=?,shift=?,can_register=?,can_view_result=?
                WHERE id=?
            """, (
                request.form.get('name', target['name']),
                request.form.get('position'),
                request.form.get('phone'),
                request.form.get('email'),
                role_to_set,
                request.form.get('joined_date') or None,
                request.form.get('shift') or None,
                can_reg, can_view,
                uid
            ))
            if photo:
                conn.execute("UPDATE users SET photo=? WHERE id=?", (photo, uid))
            # Эрх шинэчлэх — геологи/баяжуулах тоног ашиглах эрх олгохгүй
            conn.execute("DELETE FROM staff_device_permissions WHERE user_id=?", (uid,))
            if role_to_set not in ('geologist', 'bayjuulach'):
                for did in request.form.getlist('device_permissions'):
                    conn.execute("INSERT OR IGNORE INTO staff_device_permissions(user_id,device_id) VALUES(?,?)", (uid, did))
            conn.commit()
            flash('Мэдээлэл шинэчлэгдлээ!' if lang=='mn' else 'Updated!', 'success')
            # Хадгалаад жагсаалт руу шилжих
            if request.form.get('next') == 'list':
                conn.close()
                return redirect(url_for('staff_list'))
        elif action == 'reset_password':
            new_pw = request.form.get('new_password','')
            if len(new_pw) < 6:
                flash('Нууц үг хамгийн багадаа 6 тэмдэгт!' if lang=='mn' else 'Min 6 characters!', 'error')
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pw), uid))
                conn.commit()
                flash('Нууц үг шинэчлэгдлээ!' if lang=='mn' else 'Password reset!', 'success')
        conn.close()
        return redirect(url_for('staff_edit', uid=uid))
    conn.close()
    return render_template('admin/staff_edit.html', target=target, devices=devices, perms=perms, lang=lang)

# ── PROFILE EDIT ─────────────────────────────────────────
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    lang = session.get('lang','mn')
    uid  = session.get('user_id', 0)
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_info':
            photo = save_file(request.files.get('photo'), 'staff')
            conn.execute("""
                UPDATE users SET position=?, phone=?, email=?
                WHERE id=?
            """, (
                request.form.get('position'),
                request.form.get('phone'),
                request.form.get('email'),
                uid
            ))
            if photo:
                conn.execute("UPDATE users SET photo=? WHERE id=?", (photo, uid))
            conn.commit()
            flash('Мэдээлэл шинэчлэгдлээ!' if lang=='mn' else 'Profile updated!', 'success')
        elif action == 'change_password':
            old_pw = request.form.get('old_password','')
            new_pw = request.form.get('new_password','')
            confirm_pw = request.form.get('confirm_password','')
            if not check_password(user['password_hash'], old_pw):
                flash('Хуучин нууц үг буруу!' if lang=='mn' else 'Wrong current password!', 'error')
            elif new_pw != confirm_pw:
                flash('Шинэ нууц үг таарахгүй байна!' if lang=='mn' else 'Passwords do not match!', 'error')
            elif len(new_pw) < 6:
                flash('Нууц үг хамгийн багадаа 6 тэмдэгт байх ёстой!' if lang=='mn' else 'Password must be at least 6 characters!', 'error')
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (hash_password(new_pw), uid))
                conn.commit()
                flash('Нууц үг амжилттай солигдлоо!' if lang=='mn' else 'Password changed!', 'success')
        conn.close()
        return redirect(url_for('profile'))
    conn.close()
    return render_template('staff/profile.html', user=user, lang=lang)

# ── STAFF DEACTIVATE ────────────────────────────────────
@app.route('/staff/<int:uid>/deactivate', methods=['POST'])
@senior_required
def staff_deactivate(uid):
    lang = session.get('lang','mn')
    conn = get_db()
    # Өөрийгөө идэвхгүй болгохоос хамгаалах
    if uid == session.get('user_id', 0):
        conn.close()
        flash('Өөрийгөө идэвхгүй болгох боломжгүй!' if lang=='mn' else 'Cannot deactivate yourself!', 'error')
        return redirect(url_for('staff_list'))
    conn.execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash('Ажилтан идэвхгүй болголоо.' if lang=='mn' else 'Staff deactivated.', 'success')
    return redirect(url_for('staff_list'))

@app.route('/staff/<int:uid>/activate', methods=['POST'])
@senior_required
def staff_activate(uid):
    lang = session.get('lang','mn')
    conn = get_db()
    conn.execute("UPDATE users SET is_active=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash('Ажилтан идэвхжүүлэгдлээ.' if lang=='mn' else 'Staff activated.', 'success')
    return redirect(url_for('staff_list'))

@app.route('/staff/<int:uid>/delete', methods=['POST'])
@admin_required
def staff_delete(uid):
    lang = session.get('lang','mn')
    if uid == session.get('user_id'):
        flash('Өөрийгөө устгах боломжгүй!', 'error')
        return redirect(url_for('archive'))
    conn = get_db()
    conn.execute("DELETE FROM staff_device_permissions WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM users WHERE id=? AND is_active=0", (uid,))
    conn.commit()
    conn.close()
    flash('Ажилтан бүрмөсөн устгагдлаа.' if lang=='mn' else 'Staff permanently deleted.', 'success')
    return redirect(url_for('archive'))

# ── DEVICE ARCHIVE / RESTORE ────────────────────────────
@app.route('/devices/<int:did>/archive', methods=['POST'])
@senior_required
def device_archive(did):
    lang = session.get('lang','mn')
    conn = get_db()
    reason = request.form.get('reason', 'archived')
    conn.execute("UPDATE devices SET status=? WHERE id=?", (reason, did))
    conn.commit(); conn.close()
    msgs = {
        'standby':        'Төхөөрөмж нөөцөд шилжлээ.',
        'repair':         'Төхөөрөмж засварт шилжлээ. Дэлгэрэнгүйг бүртгэнэ үү.',
        'replaced':       'Төхөөрөмж солигдсон гэж тэмдэглэгдлээ.',
        'decommissioned': 'Төхөөрөмж акталагдлаа.',
        'archived':       'Төхөөрөмж архивлагдлаа.',
    }
    flash(msgs.get(reason, 'Төхөөрөмжийн төлөв шинэчлэгдлээ.') if lang=='mn' else 'Device status updated.', 'success')
    # Засварт шилжүүлсэн бол detail хуудас руу (дэлгэрэнгүй бүртгэхэд)
    if reason == 'repair':
        return redirect(url_for('device_detail', did=did) + '#tab-repair')
    return redirect(url_for('devices'))

@app.route('/devices/<int:did>/restore', methods=['POST'])
@senior_required
def device_restore(did):
    lang = session.get('lang','mn')
    conn = get_db()
    conn.execute("UPDATE devices SET status='active' WHERE id=?", (did,))
    conn.commit(); conn.close()
    flash('Төхөөрөмж сэргээгдлээ.' if lang=='mn' else 'Device restored.', 'success')
    return redirect(url_for('devices'))

# ── MARKS ───────────────────────────────────────────────
@app.route('/marks/add', methods=['POST'])
@admin_required
def mark_add():
    conn = get_db()
    conn.execute("INSERT INTO device_marks(manufacturer,model,category) VALUES(?,?,?)",
                 (request.form['manufacturer'], request.form['model'], request.form.get('category')))
    mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    name = f"{request.form['manufacturer']} {request.form['model']}"
    conn.commit(); conn.close()
    return jsonify({'success': True, 'id': mid, 'name': name})

# ── DB MIGRATION (called once at startup) ───────────────
def ensure_tables():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS lab_report_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_label TEXT, period_type TEXT, year INTEGER,
        period_start TEXT, period_end TEXT, report_type TEXT, file_path TEXT,
        generated_by INTEGER REFERENCES users(id),
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'active', archived_by INTEGER, archived_at TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS crm_materials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        crm_name TEXT NOT NULL,
        mad_cert REAL, mad_unc REAL, aad_cert REAL, aad_unc REAL,
        vad_cert REAL, vad_unc REAL, sulfur_cert REAL, sulfur_unc REAL,
        cal_cert REAL, cal_unc REAL, notes TEXT,
        manufacture_date TEXT, expiry_date TEXT, open_date TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS guest_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        label TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL
    )""")
    for col in ['manufacture_date TEXT', 'expiry_date TEXT', 'open_date TEXT', 'g_cert REAL', 'g_unc REAL', 'standard TEXT',
                'mad_cert REAL', 'mad_unc REAL',
                'aad_cert REAL', 'aad_unc REAL', 'vad_cert REAL', 'vad_unc REAL',
                'sulfur_cert REAL', 'sulfur_unc REAL', 'cal_cert REAL', 'cal_unc REAL']:
        try: conn.execute(f"ALTER TABLE crm_materials ADD COLUMN {col}")
        except Exception: pass
    for col in ['crm_name TEXT','crm_mad REAL','crm_aad REAL','crm_vad REAL',
                'crm_sulfur REAL','crm_cal REAL','crm_mad_unc REAL','crm_aad_unc REAL',
                'crm_vad_unc REAL','crm_sulfur_unc REAL','crm_cal_unc REAL','sample_range TEXT']:
        try: conn.execute(f"ALTER TABLE geo_samples ADD COLUMN {col}")
        except Exception: pass
    for col in ['prep_operator TEXT', 'prep_position TEXT', 'prep_devices TEXT']:
        try: conn.execute(f"ALTER TABLE sample_receipt ADD COLUMN {col}")
        except Exception: pass
    # Төхөөрөмжийн дэлгэрэнгүй паспорт талбарууд
    for col in ['web_link TEXT','method TEXT','max_temp TEXT','particular TEXT',
                'measuring_time TEXT','measuring_limit TEXT','dimension TEXT','capacity TEXT',
                'weight_kg TEXT','other_spec TEXT','power TEXT','frequency TEXT','voltage TEXT',
                'specification TEXT','operating_state TEXT','received_date TEXT','lab_id TEXT',
                'check_standard TEXT','check_tolerance TEXT','check_unit TEXT',
                'check_enabled INTEGER DEFAULT 1','stage TEXT DEFAULT \'both\'',
                'check_freq TEXT DEFAULT \'daily\'']:
        try: conn.execute(f"ALTER TABLE devices ADD COLUMN {col}")
        except Exception: pass
    # Дотоод өдөр тутмын шалгалт (жин г.м.)
    conn.execute("""CREATE TABLE IF NOT EXISTS device_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES devices(id),
        checked_by INTEGER REFERENCES users(id),
        check_date TEXT NOT NULL,
        standard_value TEXT,
        measured_value TEXT,
        tolerance TEXT,
        result TEXT DEFAULT 'pass',
        calibration_adjusted INTEGER DEFAULT 0,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    for col in ['calibration_adjusted INTEGER DEFAULT 0',
                'measured_value2 TEXT', 'standard_value2 TEXT', 'tolerance2 TEXT']:
        try: conn.execute(f"ALTER TABLE device_checks ADD COLUMN {col}")
        except Exception: pass
    for col in ['check_standard2 TEXT', 'check_tolerance2 TEXT',
                'check_param1 TEXT', 'check_param2 TEXT',
                'check_param3 TEXT', 'check_standard3 TEXT', 'check_tolerance3 TEXT',
                'check_param4 TEXT', 'check_standard4 TEXT', 'check_tolerance4 TEXT',
                'check_param5 TEXT', 'check_standard5 TEXT', 'check_tolerance5 TEXT']:
        try: conn.execute(f"ALTER TABLE devices ADD COLUMN {col}")
        except Exception: pass
    for col in ['check_group1 TEXT', 'check_group2 TEXT', 'check_group3 TEXT',
                'check_group1_cols INTEGER', 'check_group2_cols INTEGER', 'check_group3_cols INTEGER',
                'check_photo1 TEXT', 'check_photo2 TEXT', 'check_photo3 TEXT', 'check_photo4 TEXT', 'check_photo5 TEXT']:
        try: conn.execute(f"ALTER TABLE devices ADD COLUMN {col}")
        except Exception: pass
    for col in ['measured_value3 TEXT', 'standard_value3 TEXT', 'tolerance3 TEXT',
                'measured_value4 TEXT', 'standard_value4 TEXT', 'tolerance4 TEXT',
                'measured_value5 TEXT', 'standard_value5 TEXT', 'tolerance5 TEXT']:
        try: conn.execute(f"ALTER TABLE device_checks ADD COLUMN {col}")
        except Exception: pass
    try: conn.execute("ALTER TABLE device_checks ADD COLUMN photo TEXT")
    except Exception: pass
    try: conn.execute("ALTER TABLE users ADD COLUMN shift TEXT")
    except Exception: pass
    try: conn.execute("ALTER TABLE users ADD COLUMN can_register INTEGER DEFAULT 0")
    except Exception: pass
    try: conn.execute("ALTER TABLE users ADD COLUMN can_view_result INTEGER DEFAULT 0")
    except Exception: pass
    try: conn.execute("""
        CREATE TABLE IF NOT EXISTS result_view_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            receipt_id INTEGER REFERENCES sample_receipt(id),
            viewed_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    except Exception: pass
    try: conn.execute("""
        CREATE TABLE IF NOT EXISTS check_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            param1 TEXT, standard1 TEXT, tolerance1 TEXT,
            param2 TEXT, standard2 TEXT, tolerance2 TEXT,
            param3 TEXT, standard3 TEXT, tolerance3 TEXT,
            param4 TEXT, standard4 TEXT, tolerance4 TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    except Exception: pass
    try: conn.execute("""
        CREATE TABLE IF NOT EXISTS device_calib_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL REFERENCES devices(id),
            checked_by INTEGER REFERENCES users(id),
            check_date TEXT NOT NULL,
            x1 REAL, y1 REAL,
            x2 REAL, y2 REAL,
            x3 REAL, y3 REAL,
            x4 REAL, y4 REAL,
            x5 REAL, y5 REAL,
            slope_b REAL,
            intercept_a REAL,
            r_squared REAL,
            result TEXT DEFAULT 'pass',
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    except Exception: pass
    # Лаб 01-05: жингийн босоо загвар тэмдэглэх (check_group1_cols=0)
    conn.execute("""
        UPDATE devices SET check_group1_cols=0
        WHERE CAST(lab_id AS TEXT) IN ('01','02','03','04','05','001','002','003','004','005')
    """)
    # Лаб 02-05: лаб 01-ийн жингийн тохиргоог хуулна (photo-оос бусад)
    conn.execute("""
        UPDATE devices SET
            check_param1   = (SELECT check_param1   FROM devices WHERE lab_id='01' LIMIT 1),
            check_standard = (SELECT check_standard FROM devices WHERE lab_id='01' LIMIT 1),
            check_tolerance= (SELECT check_tolerance FROM devices WHERE lab_id='01' LIMIT 1),
            check_group1   = (SELECT check_group1   FROM devices WHERE lab_id='01' LIMIT 1),
            check_freq     = (SELECT check_freq     FROM devices WHERE lab_id='01' LIMIT 1),
            check_enabled  = (SELECT check_enabled  FROM devices WHERE lab_id='01' LIMIT 1),
            check_group1_cols = 0
        WHERE CAST(lab_id AS TEXT) IN ('02','03','04','05','002','003','004','005')
    """)
    # Лаб 11-14: лаб 06-тай ижил (зуухны температур, daily)
    conn.execute("""
        UPDATE devices SET
            check_group1='Зуухны температур', check_group2=NULL, check_group3=NULL,
            check_param1='Температур 1', check_standard='850±10 °C', check_tolerance='6 мин - 850 °C',
            check_param2='Температур 2', check_standard2='900±20 °C', check_tolerance2='3 мин - 900 °C',
            check_param3=NULL, check_standard3=NULL, check_tolerance3=NULL,
            check_param4=NULL, check_standard4=NULL, check_tolerance4=NULL,
            check_freq=COALESCE(check_freq,'daily'), check_enabled=1, check_group1_cols=4
        WHERE CAST(lab_id AS TEXT) IN ('11','12','13','14','011','012','013','014')
           OR LOWER(name) LIKE '%барабан%'
    """)
    # Зуух (муфель зуух) — нэрээр тааруулна
    conn.execute("""
        UPDATE devices SET
            check_group1='Зуухны температур', check_group2=NULL, check_group3=NULL,
            check_param1='Температур 1', check_standard='850±10 °C', check_tolerance='6 мин - 850 °C',
            check_param2='Температур 2', check_standard2='900±20 °C', check_tolerance2='3 мин - 900 °C',
            check_param3=NULL, check_standard3=NULL, check_tolerance3=NULL,
            check_param4=NULL, check_standard4=NULL, check_tolerance4=NULL,
            check_param5=NULL, check_standard5=NULL, check_tolerance5=NULL,
            check_freq=COALESCE(check_freq,'daily'), check_enabled=1, check_group1_cols=4
        WHERE CAST(lab_id AS TEXT) IN ('06','07','08','006','007','008')
           OR LOWER(name) LIKE '%муфель%' OR LOWER(name) LIKE '%muffle%'
           OR LOWER(name) LIKE '%зуух%'
    """)
    # Хатаах шүүгээ — нэрээр тааруулна
    conn.execute("""
        UPDATE devices SET
            check_group1='Зуухны температур', check_group2=NULL, check_group3=NULL,
            check_param1='Температур 1', check_standard='105±2 °C', check_tolerance='±2 °C',
            check_param2='Температур 2', check_standard2='105±2 °C', check_tolerance2='±2 °C',
            check_param3=NULL, check_standard3=NULL, check_tolerance3=NULL,
            check_param4=NULL, check_standard4=NULL, check_tolerance4=NULL,
            check_param5=NULL, check_standard5=NULL, check_tolerance5=NULL,
            check_freq=COALESCE(check_freq,'daily'), check_enabled=1, check_group1_cols=4
        WHERE CAST(lab_id AS TEXT) IN ('19','20','21','019','020','021')
           OR LOWER(name) LIKE '%хатаах%' OR LOWER(name) LIKE '%шүүгээ%'
           OR LOWER(name) LIKE '%drying%'
    """)
    # Холигч — нэрээр тааруулна
    conn.execute("""
        UPDATE devices SET
            check_group1='Зуухны температур', check_group2=NULL, check_group3=NULL,
            check_param1='Температур 1', check_standard='850±10 °C', check_tolerance='6 мин - 850 °C',
            check_param2='Температур 2', check_standard2='900±20 °C', check_tolerance2='3 мин - 900 °C',
            check_param3=NULL, check_standard3=NULL, check_tolerance3=NULL,
            check_param4=NULL, check_standard4=NULL, check_tolerance4=NULL,
            check_param5=NULL, check_standard5=NULL, check_tolerance5=NULL,
            check_freq=COALESCE(check_freq,'daily'), check_enabled=1, check_group1_cols=4
        WHERE CAST(lab_id AS TEXT) IN ('15','16','015','016')
           OR LOWER(name) LIKE '%холигч%' OR LOWER(name) LIKE '%mixer%'
    """)
    # Хөөлтийн зэрэг тодорхойлох багаж — зуухтай ижил
    conn.execute("""
        UPDATE devices SET
            check_group1='Зуухны температур', check_group2=NULL, check_group3=NULL,
            check_param1='Температур 1', check_standard='850±10 °C', check_tolerance='6 мин - 850 °C',
            check_param2='Температур 2', check_standard2='900±20 °C', check_tolerance2='3 мин - 900 °C',
            check_param3=NULL, check_standard3=NULL, check_tolerance3=NULL,
            check_param4=NULL, check_standard4=NULL, check_tolerance4=NULL,
            check_param5=NULL, check_standard5=NULL, check_tolerance5=NULL,
            check_freq=COALESCE(check_freq,'daily'), check_enabled=1, check_group1_cols=4
        WHERE name LIKE '%Хөөлт%' OR name LIKE '%хөөлт%'
           OR name LIKE '%Алхан%' OR name LIKE '%алхан%'
           OR name LIKE '%Аяган%' OR name LIKE '%аяган%'
           OR name LIKE '%Роторт%' OR name LIKE '%роторт%'
    """)
    # Калориметр — сарын шалгалт
    conn.execute("""
        UPDATE devices SET
            check_freq=COALESCE(NULLIF(check_freq,'daily'),'monthly'),
            check_enabled=1,
            check_param1=NULL, check_standard=NULL, check_tolerance=NULL,
            check_param2=NULL, check_standard2=NULL, check_tolerance2=NULL,
            check_group1='Калориметрийн шалгалт'
        WHERE LOWER(name) LIKE '%калориметр%'
    """)
    # Хүхрийн багаж — сарын калибровкийн шалгалт
    conn.execute("""
        UPDATE devices SET
            check_freq=COALESCE(NULLIF(check_freq,'daily'),'monthly'),
            check_enabled=1,
            check_param1=NULL, check_standard=NULL, check_tolerance=NULL,
            check_param2=NULL, check_standard2=NULL, check_tolerance2=NULL,
            check_group1='Шугман регрессийн калибровк'
        WHERE LOWER(name) LIKE '%хүхэр%' OR LOWER(name) LIKE '%sulfur%'
    """)
    # Буруу орсон check_param5='5' утгыг цэвэрлэнэ
    conn.execute("UPDATE devices SET check_param5=NULL, check_standard5=NULL, check_tolerance5=NULL WHERE check_param5='5'")
    try: conn.execute("ALTER TABLE internal_qc ADD COLUMN qc_number TEXT")
    except: pass
    try: conn.execute("ALTER TABLE internal_qc ADD COLUMN row_num_1 INTEGER")
    except: pass
    try: conn.execute("ALTER TABLE internal_qc ADD COLUMN row_num_2 INTEGER")
    except: pass
    conn.execute("""CREATE TABLE IF NOT EXISTS internal_qc (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qc_number TEXT,
        triggered_date TEXT NOT NULL,
        receipt_id_1 INTEGER REFERENCES sample_receipt(id),
        receipt_id_2 INTEGER REFERENCES sample_receipt(id),
        assigned_to INTEGER REFERENCES users(id),
        status TEXT DEFAULT 'pending',
        notes TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS internal_qc_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qc_id INTEGER REFERENCES internal_qc(id),
        receipt_id INTEGER REFERENCES sample_receipt(id),
        parameter TEXT,
        original_value REAL,
        repeat_value REAL,
        difference REAL,
        within_tolerance INTEGER DEFAULT 0,
        notes TEXT
    )""")
    conn.commit()
    conn.close()

# ── REPORTS ─────────────────────────────────────────────
@app.route('/reports')
@senior_required
def reports():
    conn = get_db()
    try:
        lab_records = conn.execute(
            '''SELECT r.*, u.name as gen_name FROM lab_report_records r
               LEFT JOIN users u ON u.id=r.generated_by
               WHERE r.status='active' ORDER BY r.generated_at DESC LIMIT 30'''
        ).fetchall()
    except Exception:
        lab_records = []
    SAMPLE_TYPES_MAP = [
        ('PIT','Уурхай'),('STOCKPILE','Овоолго'),('EXPORT','Ачилт'),
        ('CONTROL','Хяналт'),('DP','Баяжуулах'),('EQ_CONTROL','Гадаад хяналт'),
    ]
    ANALYSIS_FIELDS = [
        ('mt_dried','Нийт чийг'),('mad','Дотоод чийг'),('aad','Үнслэг'),('vad','Дэгдэмхий'),
        ('sulfur','Хүхэр'),('cal_value','Илчлэг'),('g_coke','G индекс'),('fsi','Чөлөөт хөөлтийн зэрэг'),
    ]
    iqc_rows = conn.execute("""
        SELECT iq.id, iq.triggered_date, iq.status,
            sr1.lab_number as lab1, g1.sample_name as sname1,
            sr2.lab_number as lab2, g2.sample_name as sname2,
            COUNT(r.id) as total,
            SUM(r.within_tolerance) as passed
        FROM internal_qc iq
        LEFT JOIN sample_receipt sr1 ON sr1.id=iq.receipt_id_1
        LEFT JOIN geo_samples g1 ON g1.id=sr1.geo_sample_id
        LEFT JOIN sample_receipt sr2 ON sr2.id=iq.receipt_id_2
        LEFT JOIN geo_samples g2 ON g2.id=sr2.geo_sample_id
        LEFT JOIN internal_qc_results r ON r.qc_id=iq.id
        GROUP BY iq.id ORDER BY iq.created_at DESC
    """).fetchall()
    conn.close()
    return render_template('admin/reports.html', lang=session.get('lang','mn'),
        lab_records=lab_records,
        sample_types=[name for _, name in SAMPLE_TYPES_MAP],
        analysis_types=[name for _, name in ANALYSIS_FIELDS],
        iqc_rows=iqc_rows)

@app.route('/reports/chart-data')
@senior_required
def reports_chart_data():
    import calendar as cal_mod
    rtype  = request.args.get('type', 'month')
    year   = int(request.args.get('year', datetime.now().year))
    month  = int(request.args.get('month', datetime.now().month))
    week   = int(request.args.get('week', 1))
    half   = int(request.args.get('half', 1))
    SAMPLE_TYPES_MAP = [
        ('PIT','Уурхай'),('STOCKPILE','Овоолго'),('EXPORT','Ачилт'),
        ('CONTROL','Хяналт'),('DP','Баяжуулах'),('EQ_CONTROL','Гадаад хяналт'),
    ]
    ANALYSIS_FIELDS = [
        ('mt_dried','Нийт чийг'),('mad','Дотоод чийг'),('aad','Үнслэг'),('vad','Дэгдэмхий'),
        ('sulfur','Хүхэр'),('cal_value','Илчлэг'),('g_coke','G индекс'),('fsi','Чөлөөт хөөлтийн зэрэг'),
    ]
    conn = get_db()
    if rtype == 'week':
        import datetime as dt_mod
        d0 = dt_mod.date(year, 1, 1) + dt_mod.timedelta(weeks=week-1)
        d1 = d0 + dt_mod.timedelta(days=6)
        d0s, d1s = d0.isoformat(), d1.isoformat()
    elif rtype == 'month':
        _, ld = cal_mod.monthrange(year, month)
        d0s = f"{year}-{month:02d}-01"
        d1s = f"{year}-{month:02d}-{ld:02d}"
    elif rtype == 'half':
        if half == 1:
            d0s, d1s = f"{year}-01-01", f"{year}-06-30"
        else:
            d0s, d1s = f"{year}-07-01", f"{year}-12-31"
    else:
        d0s, d1s = f"{year}-01-01", f"{year}-12-31"
    sample_totals = []
    for code, name in SAMPLE_TYPES_MAP:
        v = conn.execute(
            'SELECT COUNT(*) FROM geo_samples WHERE sample_type=? AND collected_date BETWEEN ? AND ?',
            (code, d0s, d1s)).fetchone()[0]
        sample_totals.append(v)
    analysis_totals = []
    for field, name in ANALYSIS_FIELDS:
        v = conn.execute(
            f'SELECT COUNT(*) FROM sample_entries WHERE {field} IS NOT NULL AND done_at BETWEEN ? AND ?',
            (d0s + ' 00:00:00', d1s + ' 23:59:59')).fetchone()[0]
        analysis_totals.append(v)
    conn.close()
    return jsonify({
        'sample_labels': [n for _, n in SAMPLE_TYPES_MAP],
        'sample_data': sample_totals,
        'analysis_labels': [n for _, n in ANALYSIS_FIELDS],
        'analysis_data': analysis_totals,
    })

@app.route('/reports/export')
@senior_required
def report_export():
    import datetime as dt_mod
    rtype   = request.args.get('type', 'month')
    year    = int(request.args.get('year', datetime.now().year))
    month   = int(request.args.get('month', datetime.now().month))
    quarter = int(request.args.get('quarter', 1))
    half    = int(request.args.get('half', 1))
    week    = int(request.args.get('week', datetime.now().isocalendar()[1]))

    date_filter_mode = 'ym'  # 'ym' or 'range'

    if rtype == 'week':
        # ISO week → эхлэх/дуусах огноо
        week_start = dt_mod.datetime.fromisocalendar(year, week, 1).date()
        week_end   = dt_mod.datetime.fromisocalendar(year, week, 7).date()
        period_label = f"{year} оны {week}-р 7 хоног ({week_start} – {week_end})"
        date_filter_mode = 'range'
        date_start = str(week_start)
        date_end   = str(week_end)
    elif rtype == 'month':
        months = [month]
        period_label = f"{year} оны {month}-р сар"
    elif rtype == 'quarter':
        qm = {1:[1,2,3], 2:[4,5,6], 3:[7,8,9], 4:[10,11,12]}
        months = qm[quarter]
        period_label = f"{year} оны {quarter}-р улирал"
    elif rtype == 'half':
        months = list(range(1,7)) if half==1 else list(range(7,13))
        period_label = f"{year} оны {'эхний' if half==1 else 'хоёрдугаар'} хагас жил"
    else:
        months = list(range(1,13))
        period_label = f"{year} он"

    if date_filter_mode == 'range':
        wu  = f"date(ul.start_time) BETWEEN '{date_start}' AND '{date_end}'"
        wc  = f"c.calibration_date BETWEEN '{date_start}' AND '{date_end}'"
        wr  = f"r.reported_date BETWEEN '{date_start}' AND '{date_end}'"
        wd  = f"date(start_time) BETWEEN '{date_start}' AND '{date_end}'"
        ws_filter = f"sr.received_date BETWEEN '{date_start}' AND '{date_end}'"
    else:
        ym_list = ",".join([f"'{year}-{m:02d}'" for m in months])
        wu  = f"strftime('%Y-%m',ul.start_time) IN ({ym_list})"
        wc  = f"strftime('%Y-%m',c.calibration_date) IN ({ym_list})"
        wr  = f"strftime('%Y-%m',r.reported_date) IN ({ym_list})"
        wd  = f"strftime('%Y-%m',start_time) IN ({ym_list})"
        ws_filter = f"strftime('%Y-%m', sr.received_date) IN ({ym_list})"

    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    conn = get_db()
    NAVY='1A2744'; TEAL='0F6E56'; CORAL='993C1D'; PURPLE='3C3489'
    WHITE='FFFFFF'; GRAY='F7F7F5'

    def th():
        s=Side(style='thin',color='CCCCCC')
        return Border(left=s,right=s,top=s,bottom=s)
    def hdr(ws,r,c,v,bg=NAVY):
        cell=ws.cell(row=r,column=c,value=v)
        cell.font=Font(name='Arial',bold=True,color=WHITE,size=10)
        cell.fill=PatternFill('solid',fgColor=bg)
        cell.alignment=Alignment(horizontal='center',vertical='center',wrap_text=True)
        cell.border=th()
    def dat(ws,r,c,v,fmt=None,bold=False,bg=None,left=False):
        cell=ws.cell(row=r,column=c,value=v)
        cell.font=Font(name='Arial',size=10,bold=bold)
        cell.alignment=Alignment(horizontal='left' if left else 'center',vertical='center',wrap_text=True)
        cell.border=th()
        if fmt: cell.number_format=fmt
        if bg: cell.fill=PatternFill('solid',fgColor=bg)
    def title(ws,text,cols):
        ws.merge_cells(start_row=1,start_column=1,end_row=1,end_column=cols)
        c=ws.cell(row=1,column=1,value=f"{text} — {period_label}")
        c.font=Font(name='Arial',bold=True,size=13,color=WHITE)
        c.fill=PatternFill('solid',fgColor=NAVY)
        c.alignment=Alignment(horizontal='center',vertical='center')
        ws.row_dimensions[1].height=32
        ws.row_dimensions[2].height=28

    wb=Workbook()
    ws1=wb.active; ws1.title='Нийт дүгнэлт'
    ws1.sheet_view.showGridLines=False
    title(ws1,'НИЙТ ДҮГНЭЛТ',6)
    for ci,h in enumerate(['№','Төхөөрөмжийн нэр','Mark','Нийт цаг','Calibration','Засвар'],1):
        hdr(ws1,2,ci,h)
    devices=conn.execute('SELECT d.*,dm.manufacturer,dm.model FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id ORDER BY d.name').fetchall()
    for ri,d in enumerate(devices,3):
        bg=WHITE if ri%2==0 else GRAY
        hrs=conn.execute(f'SELECT COALESCE(SUM(duration_hours),0) as t FROM usage_logs WHERE device_id=? AND {wd}',(d['id'],)).fetchone()['t']
        cal=conn.execute('SELECT calibration_date FROM calibrations WHERE device_id=? ORDER BY calibration_date DESC LIMIT 1',(d['id'],)).fetchone()
        orep=conn.execute('SELECT COUNT(*) as c FROM repairs WHERE device_id=? AND status=?',(d['id'],'new')).fetchone()['c']
        dat(ws1,ri,1,ri-2,bg=bg); dat(ws1,ri,2,d['name'],bg=bg,left=True)
        dat(ws1,ri,3,f"{d['manufacturer'] or ''} {d['model'] or ''}".strip(),bg=bg,left=True)
        dat(ws1,ri,4,round(hrs,2),fmt='0.00',bg=bg)
        dat(ws1,ri,5,cal['calibration_date'] if cal else '—',bg=bg)
        dat(ws1,ri,6,'Шинэ' if orep else '—',bg=bg)
    for ci,w in enumerate([5,30,22,14,16,14],1):
        ws1.column_dimensions[get_column_letter(ci)].width=w

    ws2=wb.create_sheet('Ашиглалтын бүртгэл')
    ws2.sheet_view.showGridLines=False
    title(ws2,'АШИГЛАЛТЫН БҮРТГЭЛ',7)
    for ci,h in enumerate(['№','Огноо','Төхөөрөмж','Ажилтан','Эхэлсэн','Гүйцэтгэсэн','Цаг'],1):
        hdr(ws2,2,ci,h,bg=TEAL)
    logs=conn.execute(f'''SELECT ul.*,d.name as dname,u.name as uname FROM usage_logs ul LEFT JOIN devices d ON d.id=ul.device_id LEFT JOIN users u ON u.id=ul.user_id WHERE {wu} ORDER BY ul.start_time''').fetchall()
    for ri,l in enumerate(logs,3):
        bg=WHITE if ri%2==0 else GRAY
        dat(ws2,ri,1,ri-2,bg=bg); dat(ws2,ri,2,l['start_time'][:10] if l['start_time'] else '',bg=bg)
        dat(ws2,ri,3,l['dname'] or '',bg=bg,left=True); dat(ws2,ri,4,l['uname'] or '',bg=bg,left=True)
        dat(ws2,ri,5,l['start_time'][11:16] if l['start_time'] else '',bg=bg)
        dat(ws2,ri,6,l['end_time'][11:16] if l['end_time'] else '—',bg=bg)
        dat(ws2,ri,7,round(l['duration_hours'],2) if l['duration_hours'] else 0,fmt='0.00',bg=bg)
    lr2=3+len(logs)
    ws2.merge_cells(start_row=lr2,start_column=1,end_row=lr2,end_column=6)
    dat(ws2,lr2,1,'НИЙТ ЦАГ',bold=True,bg='D6DCF0',left=True)
    dat(ws2,lr2,7,round(sum(l['duration_hours'] for l in logs if l['duration_hours']),2),fmt='0.00',bold=True,bg='D6DCF0')
    for ci,w in enumerate([5,14,28,20,12,12,12],1):
        ws2.column_dimensions[get_column_letter(ci)].width=w

    ws3=wb.create_sheet('Calibration бүртгэл')
    ws3.sheet_view.showGridLines=False
    title(ws3,'CALIBRATION БҮРТГЭЛ',6)
    for ci,h in enumerate(['№','Төхөөрөмж','Хийсэн огноо','Дараагийн огноо','Хийсэн ажилтан','Үр дүн'],1):
        hdr(ws3,2,ci,h,bg=PURPLE)
    cals=conn.execute(f'''SELECT c.*,d.name as dname,u.name as uname FROM calibrations c LEFT JOIN devices d ON d.id=c.device_id LEFT JOIN users u ON u.id=c.performed_by WHERE {wc} ORDER BY c.calibration_date''').fetchall()
    for ri,c in enumerate(cals,3):
        bg=WHITE if ri%2==0 else GRAY
        dat(ws3,ri,1,ri-2,bg=bg); dat(ws3,ri,2,c['dname'] or '',bg=bg,left=True)
        dat(ws3,ri,3,c['calibration_date'] or '',bg=bg); dat(ws3,ri,4,c['next_date'] or '—',bg=bg)
        dat(ws3,ri,5,c['uname'] or '—',bg=bg)
        cell=ws3.cell(row=ri,column=6,value='Тэнцсэн' if c['result']=='passed' else 'Тэнцээгүй')
        cell.font=Font(name='Arial',size=10,color='0F6E56' if c['result']=='passed' else '993C1D',bold=True)
        cell.fill=PatternFill('solid',fgColor=bg); cell.border=th()
        cell.alignment=Alignment(horizontal='center',vertical='center')
    for ci,w in enumerate([5,28,14,14,20,14],1):
        ws3.column_dimensions[get_column_letter(ci)].width=w

    ws4=wb.create_sheet('Засварын бүртгэл')
    ws4.sheet_view.showGridLines=False
    title(ws4,'ЗАСВАРЫН БҮРТГЭЛ',7)
    for ci,h in enumerate(['№','Төхөөрөмж','Огноо','Тайлбар','Компани','Зардал (₮)','Статус'],1):
        hdr(ws4,2,ci,h,bg=CORAL)
    reps=conn.execute(f'''SELECT r.*,d.name as dname FROM repairs r LEFT JOIN devices d ON d.id=r.device_id WHERE {wr} ORDER BY r.reported_date''').fetchall()
    for ri,r in enumerate(reps,3):
        bg=WHITE if ri%2==0 else GRAY
        dat(ws4,ri,1,ri-2,bg=bg); dat(ws4,ri,2,r['dname'] or '',bg=bg,left=True)
        dat(ws4,ri,3,r['reported_date'] or '',bg=bg); dat(ws4,ri,4,r['description'] or '',bg=bg,left=True)
        dat(ws4,ri,5,r['company'] or '—',bg=bg); dat(ws4,ri,6,r['cost'] or 0,fmt='#,##0',bg=bg)
        cell=ws4.cell(row=ri,column=7,value='Шинэ' if r['status']=='new' else 'Гүйцэтгэсэн')
        cell.font=Font(name='Arial',size=10,color='993C1D' if r['status']=='new' else '0F6E56',bold=True)
        cell.fill=PatternFill('solid',fgColor=bg); cell.border=th()
        cell.alignment=Alignment(horizontal='center',vertical='center')
    lr4=3+len(reps)
    ws4.merge_cells(start_row=lr4,start_column=1,end_row=lr4,end_column=5)
    dat(ws4,lr4,1,'НИЙТ ЗАРДАЛ',bold=True,bg='FAECE7',left=True)
    dat(ws4,lr4,6,sum(r['cost'] for r in reps if r['cost']),fmt='#,##0',bold=True,bg='FAECE7')
    dat(ws4,lr4,7,'',bg='FAECE7')
    for ci,w in enumerate([5,26,12,32,18,14,12],1):
        ws4.column_dimensions[get_column_letter(ci)].width=w

    ws5=wb.create_sheet('Дотоод шалгалт')
    ws5.sheet_view.showGridLines=False
    title(ws5,'ДОТООД ШАЛГАЛТЫН БҮРТГЭЛ',8)
    for ci,h in enumerate(['№','Огноо','Төхөөрөмж','Стандарт','Хэмжсэн','Зөрүү зөвшөөрөл','Үр дүн','Тохируулга'],1):
        hdr(ws5,2,ci,h,bg='2D6A4F')
    if date_filter_mode == 'range':
        wch = f"ch.check_date BETWEEN '{date_start}' AND '{date_end}'"
    else:
        wch = f"strftime('%Y-%m',ch.check_date) IN ({ym_list})"
    chks=conn.execute(f'''SELECT ch.*,d.name as dname,u.name as uname
        FROM device_checks ch
        LEFT JOIN devices d ON d.id=ch.device_id
        LEFT JOIN users u ON u.id=ch.checked_by
        WHERE {wch} ORDER BY ch.check_date,d.name''').fetchall()
    pass_c=fail_c=adj_c=0
    for ri,ch in enumerate(chks,3):
        bg=WHITE if ri%2==0 else GRAY
        is_pass=ch['result']=='pass'
        is_adj=ch['calibration_adjusted'] if ch['calibration_adjusted'] else 0
        if is_pass: pass_c+=1
        else: fail_c+=1
        if is_adj: adj_c+=1
        dat(ws5,ri,1,ri-2,bg=bg)
        dat(ws5,ri,2,ch['check_date'] or '',bg=bg)
        dat(ws5,ri,3,ch['dname'] or '',bg=bg,left=True)
        dat(ws5,ri,4,ch['standard_value'] or '—',bg=bg)
        dat(ws5,ri,5,ch['measured_value'] or '—',bg=bg)
        dat(ws5,ri,6,ch['tolerance'] or '—',bg=bg)
        cell=ws5.cell(row=ri,column=7,value='Тэнцсэн' if is_pass else 'Тэнцээгүй')
        cell.font=Font(name='Arial',size=10,color='0F6E56' if is_pass else '993C1D',bold=True)
        cell.fill=PatternFill('solid',fgColor=bg); cell.border=th()
        cell.alignment=Alignment(horizontal='center',vertical='center')
        cell2=ws5.cell(row=ri,column=8,value='Тийм' if is_adj else '')
        cell2.font=Font(name='Arial',size=10,color='D97706' if is_adj else '999999',bold=bool(is_adj))
        cell2.fill=PatternFill('solid',fgColor=bg); cell2.border=th()
        cell2.alignment=Alignment(horizontal='center',vertical='center')
    # Дүгнэлт мөр
    lr5=3+len(chks)
    total=len(chks)
    ws5.merge_cells(start_row=lr5,start_column=1,end_row=lr5,end_column=3)
    dat(ws5,lr5,1,f'Нийт: {total}  |  Тэнцсэн: {pass_c}  |  Тэнцээгүй: {fail_c}  |  Тохируулга: {adj_c}',bold=True,bg='E8F5E9',left=True)
    for ci in range(4,9):
        dat(ws5,lr5,ci,'',bg='E8F5E9')
    for ci,w in enumerate([5,14,28,14,14,16,14,12],1):
        ws5.column_dimensions[get_column_letter(ci)].width=w

    SAMPLE_TYPE_MN = {
        'PIT':'Уурхай (PIT)', 'STOCKPILE':'Овоолго (Stockpile)',
        'EXPORT':'Экспорт (Export)', 'CONTROL':'Гааль (Control)',
        'EQ_CONTROL':'Гадаад хяналт (EQ Control)', 'DP':'Баяжуулах (DP)',
    }
    STATUS_MN = {'pending':'Хүлээгдэж байна','received':'Хүлээн авсан',
                 'prepared':'Бэлтгэсэн','analysing':'Шинжилж байна','done':'Дууссан'}

    ws_samples=conn.execute(f'''
        SELECT sr.lab_number, g.sample_name, g.sample_type, sr.received_date,
               sr.mass_kg, g.quantity, g.status
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        WHERE {ws_filter}
        ORDER BY sr.received_date, sr.lab_number
    ''').fetchall()

    type_summary=conn.execute(f'''
        SELECT g.sample_type,
               COUNT(*) as cnt,
               COALESCE(SUM(sr.mass_kg),0) as total_kg
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        WHERE {ws_filter}
        GROUP BY g.sample_type
        ORDER BY cnt DESC
    ''').fetchall()

    # ── Sheet 6: Дээжний төрөл (нэгтгэсэн) ────────────────
    ws6=wb.create_sheet('Дээжний төрөл')
    ws6.sheet_view.showGridLines=False
    title(ws6,'ДЭЭЖНИЙ ТӨРЛӨӨР НЭГТГЭСЭН',3)
    for ci,h in enumerate(['Дээжний төрөл','Шинжилгээний тоо','Нийт жин (кг)'],1):
        hdr(ws6,2,ci,h,bg=TEAL)
    for ri,t in enumerate(type_summary,3):
        bg=WHITE if ri%2==0 else GRAY
        dat(ws6,ri,1,SAMPLE_TYPE_MN.get(t['sample_type'], t['sample_type'] or ''),bg=bg,left=True)
        dat(ws6,ri,2,t['cnt'],bg=bg)
        dat(ws6,ri,3,round(t['total_kg'],2),fmt='0.00',bg=bg)
    tr=3+len(type_summary)
    dat(ws6,tr,1,'НИЙТ',bold=True,bg='D6F0E8',left=True)
    dat(ws6,tr,2,sum(t['cnt'] for t in type_summary),bold=True,bg='D6F0E8')
    dat(ws6,tr,3,round(sum(t['total_kg'] for t in type_summary),2),fmt='0.00',bold=True,bg='D6F0E8')
    for ci,w in enumerate([28,20,18],1):
        ws6.column_dimensions[get_column_letter(ci)].width=w

    # ── Sheet 7: Шинжилгээний үр дүн (төрлөөр нэгтгэсэн) ─
    ws7=wb.create_sheet('Шинжилгээ')
    ws7.sheet_view.showGridLines=False
    title(ws7,'ШИНЖИЛГЭЭНИЙ ҮР ДҮНГИЙН ХҮСНЭГТ',11)
    hdrs7=['№','Дээжний төрөл','Нийт дээж','Mt','Mad','Aad','Vad','Fc','St','Q','G']
    for ci,h in enumerate(hdrs7,1):
        hdr(ws7,2,ci,h,bg=TEAL)
    ws7.row_dimensions[2].height=22

    def has_mt(row):
        try: return row['ff_sample'] is not None and float(row['ff_sample'])>0 and row['ff_dried'] is not None
        except: return False
    def has_g(row):
        if row['g_val'] is not None: return True
        try: return all(row[f] is not None for f in ['g_coke','g_tare','g_sieve1','g_sieve2'])
        except: return False

    type_receipts = conn.execute(f'''
        SELECT g.sample_type, COUNT(DISTINCT sr.id) as cnt
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        WHERE {ws_filter}
        GROUP BY g.sample_type
        ORDER BY cnt DESC
    ''').fetchall()

    analysis_rows=conn.execute(f'''
        SELECT g.sample_type, se.mad, se.aad, se.vad, se.fc,
               se.sulfur, se.cal_value, se.g_val,
               se.ff_sample, se.ff_dried,
               se.g_coke, se.g_tare, se.g_sieve1, se.g_sieve2
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        JOIN sample_entries se ON se.receipt_id=sr.id
        WHERE {ws_filter}
          AND se.row_status IN ('done','approved')
    ''').fetchall()

    from collections import defaultdict
    type_cnt = defaultdict(lambda: {k:0 for k in ['mt','mad','aad','vad','fc','sulfur','cal_value','g']})
    for s in analysis_rows:
        t = s['sample_type']
        if has_mt(s): type_cnt[t]['mt'] += 1
        for f in ['mad','aad','vad','fc','sulfur','cal_value']:
            if s[f] is not None: type_cnt[t][f] += 1
        if has_g(s): type_cnt[t]['g'] += 1

    receipt_map = {r['sample_type']: r['cnt'] for r in type_receipts}
    for ri, r in enumerate(type_receipts, 3):
        bg = WHITE if ri%2==0 else GRAY
        t = r['sample_type']
        c = type_cnt[t]
        dat(ws7,ri,1,ri-2,bg=bg)
        dat(ws7,ri,2,SAMPLE_TYPE_MN.get(t,t),bg=bg,left=True)
        dat(ws7,ri,3,r['cnt'],bg=bg)
        dat(ws7,ri,4,c['mt'] or None,bg=bg)
        dat(ws7,ri,5,c['mad'] or None,bg=bg)
        dat(ws7,ri,6,c['aad'] or None,bg=bg)
        dat(ws7,ri,7,c['vad'] or None,bg=bg)
        dat(ws7,ri,8,c['fc'] or None,bg=bg)
        dat(ws7,ri,9,c['sulfur'] or None,bg=bg)
        dat(ws7,ri,10,c['cal_value'] or None,bg=bg)
        dat(ws7,ri,11,c['g'] or None,bg=bg)

    for ci,w in enumerate([5,24,14,10,10,10,10,10,10,10,10],1):
        ws7.column_dimensions[get_column_letter(ci)].width=w

    for ws in [ws1,ws2,ws3,ws4,ws5,ws6,ws7]:
        ws.page_setup.orientation='landscape'
        ws.page_setup.fitToPage=True; ws.page_setup.fitToWidth=1

    conn.close()
    buf=io.BytesIO(); wb.save(buf); buf.seek(0)
    fname='Лаборатори_' + period_label.replace(' ','_') + '.xlsx'
    return send_file(buf,as_attachment=True,download_name=fname,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')



# ── ANALYSIS MODULE ──────────────────────────────────────

# Лаб дугаар автоматаар үүсгэх
def generate_lab_number(sample_type, date_str):
    """Дээжний төрлөөс хамааран лаб дугаар үүсгэнэ"""
    prefix_map = {
        'PIT': 1000, 'STOCKPILE': 2000, 'EXPORT': 3000,
        'CONTROL': 4000, 'EQ_CONTROL': 5000, 'DP': 6000, 'CRM': 9000
    }
    base = prefix_map.get(sample_type, 1000)
    conn = get_db()
    # Тухайн өдрийн хамгийн сүүлийн дугаар олох
    last = conn.execute("""
        SELECT lab_serial FROM sample_receipt
        WHERE lab_number LIKE ?
        ORDER BY lab_serial DESC LIMIT 1
    """, (f"%-{date_str}",)).fetchone()
    conn.close()
    if last:
        next_serial = last['lab_serial'] + 1
    else:
        next_serial = base + 1
    return f"{next_serial}-{date_str}", next_serial

# Тооцоолол функц
def calculate_results(m):
    """Sheet 2-ын томьёогоор тооцоолно"""
    r = {}
    try:
        # Нийт чийг Mt
        fm = 0
        if m.get('fm_sample_mass') and m.get('fm_dried_mass'):
            fm = (m['fm_sample_mass'] - m['fm_dried_mass']) / m['fm_sample_mass'] * 100

        im1 = im2 = 0
        if m.get('mt_tare1') and m.get('mt_sample1') and m.get('mt_dried1'):
            im1 = (m['mt_tare1'] + m['mt_sample1'] - m['mt_dried1']) / m['mt_sample1'] * 100
        if m.get('mt_tare2') and m.get('mt_sample2') and m.get('mt_dried2'):
            im2 = (m['mt_tare2'] + m['mt_sample2'] - m['mt_dried2']) / m['mt_sample2'] * 100
        im_avg = (im1 + im2) / 2 if im2 else im1
        r['Mt'] = round(fm + im_avg * (1 - fm/100), 4) if fm else round(im_avg, 4)

        # Дотоод чийг Mad
        mad1 = mad2 = 0
        if m.get('im_tare1') and m.get('im_sample1') and m.get('im_dried1'):
            mad1 = (m['im_tare1'] + m['im_sample1'] - m['im_dried1']) / m['im_sample1'] * 100
        if m.get('im_tare2') and m.get('im_sample2') and m.get('im_dried2'):
            mad2 = (m['im_tare2'] + m['im_sample2'] - m['im_dried2']) / m['im_sample2'] * 100
        r['Mad'] = round((mad1 + mad2) / 2 if mad2 else mad1, 4)

        # Үнс Aad
        a1 = a2 = 0
        if m.get('ash_tare1') and m.get('ash_sample1') and m.get('ash_burned1'):
            a1 = (m['ash_burned1'] - m['ash_tare1']) / m['ash_sample1'] * 100
        if m.get('ash_tare2') and m.get('ash_sample2') and m.get('ash_burned2'):
            a2 = (m['ash_burned2'] - m['ash_tare2']) / m['ash_sample2'] * 100
        r['Aad'] = round((a1 + a2) / 2 if a2 else a1, 4)
        r['Adb'] = round(r['Aad'] * 100 / (100 - r['Mad']), 4) if r.get('Mad') else 0

        # Дэгдэмхий Vad
        v1 = v2 = 0
        if m.get('vol_tare1') and m.get('vol_sample1') and m.get('vol_burned1'):
            v1 = (m['vol_tare1'] + m['vol_sample1'] - m['vol_burned1']) / m['vol_sample1'] * 100 - r.get('Mad', 0)
        if m.get('vol_tare2') and m.get('vol_sample2') and m.get('vol_burned2'):
            v2 = (m['vol_tare2'] + m['vol_sample2'] - m['vol_burned2']) / m['vol_sample2'] * 100 - r.get('Mad', 0)
        r['Vad'] = round((v1 + v2) / 2 if v2 else v1, 4)
        r['Vdb'] = round(r['Vad'] * 100 / (100 - r['Mad']), 4) if r.get('Mad') else 0
        r['Vdaf'] = round(r['Vad'] * 100 / (100 - r['Mad'] - r['Aad']), 4) if r.get('Mad') and r.get('Aad') else 0
        r['FCad'] = round(100 - r['Mad'] - r['Aad'] - r['Vad'], 4)

        # Хүхэр Stad
        s1 = m.get('sulfur1', 0) or 0
        s2 = m.get('sulfur2', 0) or 0
        r['Stad'] = round((s1 + s2) / 2 if s2 else s1, 4)
        r['Std'] = round(r['Stad'] * 100 / (100 - r['Mad']), 4) if r.get('Mad') else 0

        # Илчлэг
        q1 = m.get('cal_value1', 0) or 0
        q2 = m.get('cal_value2', 0) or 0
        qb_jg = (q1 + q2) / 2 if q2 else q1
        r['Qb_ad_jg'] = round(qb_jg, 2)
        r['Qb_ad_kcal'] = round(qb_jg / 4.1868, 2)
        # Qgr,ad = (Qb,ad - St*94.1 - Qb*0.0016) / 4.1868
        r['Qgr_ad'] = round((qb_jg - r['Stad'] * 94.1 - qb_jg * 0.0016) / 4.1868, 2)
        # Qgr,ar = Qgr,ad * (100-Mt)/(100-Mad)
        if r.get('Mt') is not None and r.get('Mad'):
            r['Qgr_ar'] = round(r['Qgr_ad'] * (100 - r['Mt']) / (100 - r['Mad']), 2)
        # Had = 2.888 + 0.393*sqrt(Vdaf) - 0.0023*Adb
        import math
        if r.get('Vdaf') and r.get('Adb'):
            r['Had'] = round(2.888 + 0.393 * math.sqrt(r['Vdaf']) - 0.0023 * r['Adb'], 4)
            r['Hdaf'] = round(r['Had'] * 100 / (100 - r['Mad'] - r['Aad']), 4)
        # Qnet,ar = ((Qgr,ad/238.846*1000 - 206*Had)*(100-Mt)/(100-Mad) - 23*Mt)/4.1868
        if r.get('Qgr_ad') and r.get('Had') and r.get('Mt') is not None and r.get('Mad'):
            qbs = r['Qgr_ad'] / 238.846 * 1000
            r['Qnet_ar'] = round(((qbs - 206 * r['Had']) * (100 - r['Mt']) / (100 - r['Mad']) - 23 * r['Mt']) / 4.1868, 2)

        # G индекс
        if m.get('g_tare') and m.get('g_coke') and m.get('g_sieve1') and m.get('g_sieve2'):
            g1 = 10 + (30*(m['g_sieve1']-m['g_tare']) + 70*(m['g_sieve2']-m['g_tare'])) / (m['g_coke']-m['g_tare'])
        else:
            g1 = 0
        if m.get('g_tare2') and m.get('g_coke2') and m.get('g_sieve1b') and m.get('g_sieve2b'):
            g2 = 10 + (30*(m['g_sieve1b']-m['g_tare2']) + 70*(m['g_sieve2b']-m['g_tare2'])) / (m['g_coke2']-m['g_tare2'])
        else:
            g2 = 0
        r['G_index'] = round((g1 + g2) / 2 if g2 else g1, 2)

        # FSI
        f1 = m.get('fsi_value1', 0) or 0
        f2 = m.get('fsi_value2', 0) or 0
        r['FSI'] = round((f1 + f2) / 2 if f2 else f1, 1)

        # Y индекс
        if r.get('G_index'):
            r['Y_index'] = round(4.89 + r['G_index'] ** 2 * 0.00102, 2)

    except Exception as e:
        print(f"Calculation error: {e}")
    return r

def check_qc(results, is_duplicate, meas1, meas2=None):
    """QC шалгалт — зэрэгцээ шинжилгээний зөрүү шалгах"""
    if not is_duplicate or not meas2:
        return 'passed', ''
    conn = get_db()
    settings = {r['parameter']: r['tolerance'] for r in conn.execute("SELECT * FROM qc_settings").fetchall()}
    conn.close()
    warnings = []
    checks = [
        ('Mad', 'Mad'), ('Aad', 'Aad'), ('Vad', 'Vad'),
        ('Stad', 'Stad'), ('Qb_ad_kcal', 'Qb_ad'), ('G_index', 'G_index'), ('FSI', 'FSI')
    ]
    status = 'passed'
    for key, setting_key in checks:
        v1 = results.get(key, 0) or 0
        v2 = meas2.get(key, 0) or 0
        tol = settings.get(setting_key, 999)
        diff = abs(v1 - v2)
        if diff > tol:
            warnings.append(f"{key}: зөрүү {diff:.3f} > {tol}")
            status = 'warning'
    return status, '; '.join(warnings)

@app.route('/analysis')
@login_required
def analysis():
    lang = session.get('lang','mn')
    conn = get_db()
    role = session.get('role')
    uid = session.get('user_id', 0)

    if role == 'bayjuulach':
        # Баяжуулагч зөвхөн 6000-6999 серийн дууссан ажлын үр дүнг харна
        conn.close()
        return redirect(url_for('archive') + '#tab-analysis')
    if role == 'geologist':
        samples = conn.execute("""
            SELECT g.*, u.name as reg_name,
                   sr.lab_number, sr.lab_serial, sr.received_date, sr.mass_kg, sr.id as receipt_id, sr.prep_status
            FROM geo_samples g
            LEFT JOIN users u ON u.id=g.registered_by
            LEFT JOIN sample_receipt sr ON sr.geo_sample_id=g.id
            WHERE g.registered_by=? AND g.status != 'done'
            ORDER BY sr.lab_serial DESC, g.created_at DESC LIMIT 50
        """, (uid,)).fetchall()
    else:
        samples = conn.execute("""
            SELECT g.*, u.name as reg_name,
                   sr.lab_number, sr.lab_serial, sr.received_date, sr.mass_kg, sr.id as receipt_id, sr.prep_status
            FROM geo_samples g
            LEFT JOIN users u ON u.id=g.registered_by
            LEFT JOIN sample_receipt sr ON sr.geo_sample_id=g.id
            WHERE g.status != 'done'
            ORDER BY sr.lab_serial DESC, g.created_at DESC LIMIT 200
        """).fetchall()
    prep_devices = conn.execute("""
        SELECT id, name FROM devices
        WHERE status='active' AND COALESCE(stage,'both') IN ('prep','both')
        ORDER BY name
    """).fetchall()
    pending_qc = conn.execute("""
        SELECT iq.id, iq.triggered_date, iq.qc_number,
            iq.receipt_id_1, iq.receipt_id_2, iq.row_num_1, iq.row_num_2,
            sr1.lab_number as lab1, g1.sample_name as sname1,
            sr2.lab_number as lab2, g2.sample_name as sname2
        FROM internal_qc iq
        LEFT JOIN sample_receipt sr1 ON sr1.id=iq.receipt_id_1
        LEFT JOIN geo_samples g1 ON g1.id=sr1.geo_sample_id
        LEFT JOIN sample_receipt sr2 ON sr2.id=iq.receipt_id_2
        LEFT JOIN geo_samples g2 ON g2.id=sr2.geo_sample_id
        WHERE iq.status='pending'
        ORDER BY iq.created_at DESC
    """).fetchall()
    conn.close()
    return render_template('analysis/index.html', samples=samples, lang=lang,
        today=datetime.now().strftime('%Y-%m-%d'), prep_devices=prep_devices,
        pending_qc=pending_qc)

@app.route('/analysis/register', methods=['GET','POST'])
@login_required
def analysis_register():
    """Геологи дээж бүртгэнэ"""
    lang = session.get('lang','mn')
    if session.get('role') not in ('admin','senior','staff','preparer','geologist'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        conn = get_db()
        sample_type = request.form['sample_type']
        sample_name = request.form['sample_name']
        quantity    = int(request.form.get('quantity', 1))

        # Цэг таслалаар тусгаарласан нэрс: "a1; a2; b3" → тоог автоматаар тооцно
        if ';' in sample_name:
            parts = [p.strip() for p in sample_name.split(';') if p.strip()]
            quantity = len(parts)
        # PIT бол "1-100" хэлбэрийг задлах
        elif sample_type == 'PIT':
            import re as _re; m = _re.match(r'^([0-9]+)-([0-9]+)$', sample_name.strip())
            if m:
                from_n = int(m.group(1))
                to_n   = int(m.group(2))
                quantity = to_n - from_n + 1

        conn.execute("""
            INSERT INTO geo_samples(sample_name,sample_type,location,collected_date,
            quantity,notes,registered_by,status)
            VALUES(?,?,?,?,?,?,?,'pending')
        """, (
            sample_name,
            sample_type,
            request.form.get('location'),
            request.form.get('collected_date'),
            quantity,
            request.form.get('notes'),
            session['user_id']
        ))
        conn.commit(); conn.close()
        flash(f'Дээж бүртгэгдлээ! Нийт {quantity} дээж.', 'success')
        return redirect(url_for('analysis'))
    conn = get_db()
    stypes = conn.execute("SELECT * FROM sample_types WHERE is_active=1 ORDER BY sort_order,serial_from").fetchall()
    conn.close()
    return render_template('analysis/register.html', lang=lang, 
        today=datetime.now().strftime('%Y-%m-%d'),
        sample_types=stypes)

@app.route('/analysis/crm/register', methods=['GET', 'POST'])
@lab_required
def analysis_crm_register():
    conn = get_db()
    if request.method == 'POST':
        mat_id = request.form.get('crm_material_id', '').strip()
        collected_date = request.form.get('collected_date') or datetime.now().strftime('%Y-%m-%d')
        notes = request.form.get('notes', '').strip()

        if not mat_id:
            flash('CRM материал сонгоно уу', 'error')
            conn.close()
            return redirect(url_for('analysis_crm_register'))

        mat = conn.execute("SELECT * FROM crm_materials WHERE id=?", (mat_id,)).fetchone()
        if not mat:
            flash('CRM материал олдсонгүй', 'error')
            conn.close()
            return redirect(url_for('analysis_crm_register'))

        crm_name = mat['crm_name']
        try:
            cur = conn.execute("""
                INSERT INTO geo_samples (sample_name, sample_type, location, collected_date, quantity, notes,
                    registered_by, status, crm_name, crm_aad, crm_vad, crm_sulfur, crm_cal)
                VALUES (?, 'CRM', 'CRM', ?, 1, ?, ?, 'received', ?, ?, ?, ?, ?)
            """, (crm_name, collected_date, notes, session['user_id'],
                  crm_name, mat['aad_cert'], mat['vad_cert'], mat['sulfur_cert'], mat['cal_cert']))
            geo_id = cur.lastrowid

            crm_lab_num = f"CRM {crm_name} {collected_date.replace('-','')}"
            # ensure uniqueness if same CRM registered multiple times on same day
            _suffix = 0
            while conn.execute("SELECT 1 FROM sample_receipt WHERE lab_number=?", (crm_lab_num + (f'-{_suffix}' if _suffix else ''),)).fetchone():
                _suffix += 1
            if _suffix:
                crm_lab_num = crm_lab_num + f'-{_suffix}'
            cur2 = conn.execute("""
                INSERT INTO sample_receipt (geo_sample_id, lab_number, lab_serial, received_date, received_by, prep_status)
                VALUES (?, ?, ?, ?, ?, 'ready')
            """, (geo_id, crm_lab_num, 0, collected_date, session['user_id']))
            receipt_id = cur2.lastrowid

            conn.execute("""
                INSERT INTO sample_entries (receipt_id, row_num, is_duplicate, sample_name, row_status)
                VALUES (?, 1, 0, ?, 'empty')
            """, (receipt_id, crm_name))

            conn.commit()
            conn.close()
            flash(f'CRM дээж бүртгэгдлээ: {crm_name}', 'success')
            return redirect(url_for('analysis_measure', receipt_id=receipt_id))
        except Exception as e:
            import traceback; traceback.print_exc()
            conn.rollback()
            conn.close()
            flash(f'Алдаа: {e}', 'error')
            return redirect(url_for('analysis_crm_register'))

    crm_materials = conn.execute("SELECT * FROM crm_materials WHERE is_active=1 ORDER BY crm_name").fetchall()
    conn.close()
    return render_template('analysis/crm_register.html', today=datetime.now().strftime('%Y-%m-%d'),
                           crm_materials=crm_materials)

@app.route('/analysis/crm/chart')
@login_required
def crm_control_chart():
    conn = get_db()
    materials = conn.execute("SELECT * FROM crm_materials WHERE is_active=1 ORDER BY crm_name").fetchall()
    mat_id = request.args.get('mat_id', type=int)
    selected = None
    history = []
    if not mat_id and materials:
        mat_id = materials[0]['id']
    if mat_id:
        selected = conn.execute("SELECT * FROM crm_materials WHERE id=?", (mat_id,)).fetchone()
        if selected:
            rows = conn.execute("""
                SELECT g.collected_date, sr.received_date, sr.lab_number,
                       se.mad, se.aad, se.vad, se.sulfur, se.cal_value, se.g_val as g_value
                FROM geo_samples g
                JOIN sample_receipt sr ON sr.geo_sample_id=g.id
                JOIN sample_entries se ON se.receipt_id=sr.id AND se.is_duplicate=0 AND se.row_num=1
                WHERE g.crm_name=? AND g.sample_type='CRM'
                  AND se.row_status IN ('done','approved')
                ORDER BY COALESCE(sr.received_date, g.collected_date)
            """, (selected['crm_name'],)).fetchall()
            # ad → db хувиргалт
            history = []
            for r in rows:
                mad = r['mad'] or 0
                factor = 1 - mad / 100 if mad < 100 else 1
                def to_db(v):
                    if v is None or factor == 0: return None
                    return round(v / factor, 4)
                history.append({
                    'collected_date': r['collected_date'] or r['received_date'],
                    'lab_number':     r['lab_number'],
                    'mad':            r['mad'],
                    'aad':            r['aad'],
                    'vad':            r['vad'],
                    'sulfur':         r['sulfur'],
                    'cal_value':      r['cal_value'],
                    'g_value':        r['g_value'],
                    # dry basis
                    'adb':  to_db(r['aad']),
                    'vdb':  to_db(r['vad']),
                    'sdb':  to_db(r['sulfur']),
                    'qbd':  round(r['cal_value'] / factor / 1000, 4) if r['cal_value'] and factor else None,
                })
    conn.close()
    return render_template('analysis/crm_chart.html',
        materials=materials, selected=selected, selected_id=mat_id, history=history,
        today=date.today().isoformat())


@app.route('/analysis/receive/<int:geo_id>', methods=['GET','POST'])
@preparer_required
def analysis_receive(geo_id):
    """Дээж бэлтгэгч хүлээн авна — зөвхөн ажлын дугаар + жин"""
    lang = session.get('lang','mn')
    conn = get_db()
    geo = conn.execute("SELECT * FROM geo_samples WHERE id=?", (geo_id,)).fetchone()
    if not geo:
        conn.close(); return redirect(url_for('analysis'))

    # Санал болгох серийн дугаар
    prefix_map = {'PIT':1000,'STOCKPILE':2000,'EXPORT':3000,
                  'CONTROL':4000,'EQ_CONTROL':5000,'DP':6000}
    base = prefix_map.get(geo['sample_type'], 1000)
    last = conn.execute(
        "SELECT lab_serial FROM sample_receipt WHERE lab_serial>=? AND lab_serial<? ORDER BY lab_serial DESC LIMIT 1",
        (base, base+1000)
    ).fetchone()
    suggested = (last['lab_serial'] + 1) if last else (base + 1)

    if request.method == 'POST':
        serial = int(request.form.get('lab_serial', suggested))
        date_str = request.form.get('received_date','').replace('-','')
        lab_num = f"{serial}-{date_str}"
        conn.execute("""
            INSERT INTO sample_receipt(
                geo_sample_id, lab_number, lab_serial, received_date,
                received_by, notes
            ) VALUES(?,?,?,?,?,?)
        """, (
            geo_id, lab_num, serial,
            request.form.get('received_date', datetime.now().strftime('%Y-%m-%d')),
            session['user_id'],
            request.form.get('notes')
        ))
        conn.execute("UPDATE geo_samples SET status='prepared' WHERE id=?", (geo_id,))
        conn.commit(); conn.close()
        flash(f'Дээж хүлээн авлаа! Ажлын дугаар: {lab_num}', 'success')
        return redirect(url_for('analysis'))
    conn.close()
    return render_template('analysis/receive.html', geo=geo, lang=lang,
        today=datetime.now().strftime('%Y-%m-%d'),
        suggested_serial=suggested)

@app.route('/analysis/measure/<int:receipt_id>', methods=['GET','POST'])
@lab_required
def analysis_measure(receipt_id):
    """Химич шинжилгээний утгуудыг оруулна — Excel Sheet 2 шиг"""
    lang = session.get('lang','mn')
    conn = get_db()
    receipt = conn.execute("""
        SELECT sr.*, g.sample_name, g.sample_type, g.location,
               g.collected_date, g.quantity,
               ug.name as geo_name,
               up.name as prep_name
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        LEFT JOIN users ug ON ug.id=g.registered_by
        LEFT JOIN users up ON up.id=sr.received_by
        WHERE sr.id=?
    """, (receipt_id,)).fetchone()
    if not receipt:
        conn.close(); return redirect(url_for('analysis'))
    if request.method == 'POST':
        def flt(key): return float(request.form.get(key)) if request.form.get(key) else None
        m = {
            'fm_sample_mass': receipt['fm_sample_mass'],
            'fm_dried_mass': receipt['fm_dried_mass'],
            'mt_tare1': receipt['mt_tare1'], 'mt_sample1': receipt['mt_sample1'],
            'mt_dried1': receipt['mt_dried1'], 'mt_tare2': receipt['mt_tare2'],
            'mt_sample2': receipt['mt_sample2'], 'mt_dried2': receipt['mt_dried2'],
            'im_tare1': flt('im_tare1'), 'im_sample1': flt('im_sample1'), 'im_dried1': flt('im_dried1'),
            'im_tare2': flt('im_tare2'), 'im_sample2': flt('im_sample2'), 'im_dried2': flt('im_dried2'),
            'ash_tare1': flt('ash_tare1'), 'ash_sample1': flt('ash_sample1'), 'ash_burned1': flt('ash_burned1'),
            'ash_tare2': flt('ash_tare2'), 'ash_sample2': flt('ash_sample2'), 'ash_burned2': flt('ash_burned2'),
            'vol_tare1': flt('vol_tare1'), 'vol_sample1': flt('vol_sample1'), 'vol_burned1': flt('vol_burned1'),
            'vol_tare2': flt('vol_tare2'), 'vol_sample2': flt('vol_sample2'), 'vol_burned2': flt('vol_burned2'),
            'sulfur1': flt('sulfur1'), 'sulfur2': flt('sulfur2'),
            'cal_value1': flt('cal_value1'), 'cal_value2': flt('cal_value2'),
            'g_tare': flt('g_tare'), 'g_coke': flt('g_coke'),
            'g_sieve1': flt('g_sieve1'), 'g_sieve2': flt('g_sieve2'),
            'g_tare2': flt('g_tare2'), 'g_coke2': flt('g_coke2'),
            'g_sieve1b': flt('g_sieve1b'), 'g_sieve2b': flt('g_sieve2b'),
            'fsi_value1': flt('fsi_value1'), 'fsi_value2': flt('fsi_value2'),
        }
        conn.execute("""
            INSERT INTO analysis_measurements(
                receipt_id,
                im_tare1,im_sample1,im_dried1,im_crucible1,
                im_tare2,im_sample2,im_dried2,im_crucible2,
                im_date,im_shift,im_operator,im_device,
                ash_tare1,ash_sample1,ash_burned1,ash_crucible1,
                ash_tare2,ash_sample2,ash_burned2,ash_crucible2,
                ash_date,ash_shift,ash_operator,ash_device,
                vol_tare1,vol_sample1,vol_burned1,vol_crucible1,
                vol_tare2,vol_sample2,vol_burned2,vol_crucible2,
                vol_date,vol_shift,vol_operator,vol_device,
                sulfur1,sulfur2,sulfur_date,sulfur_shift,sulfur_operator,
                cal_value1,cal_value2,cal_date,cal_shift,cal_operator,
                g_tare,g_coke,g_sieve1,g_sieve2,g_crucible,g_date,g_shift,g_operator,g_device,
                g_tare2,g_coke2,g_sieve1b,g_sieve2b,
                fsi_value1,fsi_value2,fsi_date,fsi_shift,fsi_operator
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            receipt_id,
            m['im_tare1'],m['im_sample1'],m['im_dried1'],request.form.get('im_crucible1'),
            m['im_tare2'],m['im_sample2'],m['im_dried2'],request.form.get('im_crucible2'),
            request.form.get('im_date'),request.form.get('im_shift','A'),session['user_id'],request.form.get('im_device'),
            m['ash_tare1'],m['ash_sample1'],m['ash_burned1'],request.form.get('ash_crucible1'),
            m['ash_tare2'],m['ash_sample2'],m['ash_burned2'],request.form.get('ash_crucible2'),
            request.form.get('ash_date'),request.form.get('ash_shift','A'),session['user_id'],request.form.get('ash_device'),
            m['vol_tare1'],m['vol_sample1'],m['vol_burned1'],request.form.get('vol_crucible1'),
            m['vol_tare2'],m['vol_sample2'],m['vol_burned2'],request.form.get('vol_crucible2'),
            request.form.get('vol_date'),request.form.get('vol_shift','A'),session['user_id'],request.form.get('vol_device'),
            m['sulfur1'],m['sulfur2'],request.form.get('sulfur_date'),request.form.get('sulfur_shift','A'),session['user_id'],
            m['cal_value1'],m['cal_value2'],request.form.get('cal_date'),request.form.get('cal_shift','A'),session['user_id'],
            m['g_tare'],m['g_coke'],m['g_sieve1'],m['g_sieve2'],
            request.form.get('g_crucible'),request.form.get('g_date'),request.form.get('g_shift','A'),session['user_id'],request.form.get('g_device'),
            m['g_tare2'],m['g_coke2'],m['g_sieve1b'],m['g_sieve2b'],
            m['fsi_value1'],m['fsi_value2'],request.form.get('fsi_date'),request.form.get('fsi_shift','A'),session['user_id']
        ))
        # Тооцоолол
        results = calculate_results(m)
        qc_status, qc_notes = 'passed', ''
        # Үр дүн хадгалах
        conn.execute("""
            INSERT OR REPLACE INTO analysis_results(
                receipt_id, Mt, Mad, Aad, Adb, Vad, Vdb, Vdaf, FCad,
                Stad, Std, Qb_ad_jg, Qb_ad_kcal, Qgr_ad, Qgr_ar, Qnet_ar,
                Had, Hdaf, G_index, FSI, Y_index, qc_status, qc_notes
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            receipt_id,
            results.get('Mt'), results.get('Mad'), results.get('Aad'), results.get('Adb'),
            results.get('Vad'), results.get('Vdb'), results.get('Vdaf'), results.get('FCad'),
            results.get('Stad'), results.get('Std'),
            results.get('Qb_ad_jg'), results.get('Qb_ad_kcal'),
            results.get('Qgr_ad'), results.get('Qgr_ar'), results.get('Qnet_ar'),
            results.get('Had'), results.get('Hdaf'),
            results.get('G_index'), results.get('FSI'), results.get('Y_index'),
            qc_status, qc_notes
        ))
        conn.execute("UPDATE geo_samples SET status='done' WHERE id=(SELECT geo_sample_id FROM sample_receipt WHERE id=?)", (receipt_id,))
        conn.commit(); conn.close()
        flash('Шинжилгээ бүртгэгдлээ! Үр дүн тооцоологдлоо.', 'success')
        return redirect(url_for('analysis_result', receipt_id=receipt_id))
    qc_map = {r['parameter']: r['tolerance'] for r in conn.execute("SELECT parameter, tolerance FROM qc_settings").fetchall()}
    conn.close()
    return render_template('analysis/measure.html', receipt=receipt, lang=lang, qc_map=qc_map, today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/analysis/approve/<int:receipt_id>', methods=['POST'])
@senior_required
def analysis_approve(receipt_id):
    conn = get_db()
    conn.execute("""UPDATE analysis_results SET approved_by=?, approved_at=?, qc_status='approved'
                   WHERE receipt_id=?""",
                (session['user_id'], datetime.now().isoformat(), receipt_id))
    conn.commit(); conn.close()
    flash('Баталгаажлаа! Тайлан гаргах боломжтой.', 'success')
    return redirect(url_for('analysis_result', receipt_id=receipt_id))



# ── ANALYSIS AUTO-SAVE ──────────────────────────────────
@app.route('/analysis/autosave', methods=['POST'])
@lab_required
def analysis_autosave():
    """Нүд орхих бүрт автоматаар хадгална"""
    try:
        data = request.get_json()
        rid    = data.get('receipt_id')
        row    = data.get('row_num')
        is_dup = data.get('is_duplicate', 0)
        field  = data.get('field')
        value  = data.get('value')

        if not all([rid, row, field]):
            return jsonify({'ok': False, 'error': 'Missing params'})

        conn = get_db()
        # Мөр байгаа эсэх шалгах
        existing = conn.execute(
            "SELECT id FROM sample_entries WHERE receipt_id=? AND row_num=? AND is_duplicate=?",
            (rid, row, is_dup)
        ).fetchone()

        if existing:
            conn.execute(
                f"UPDATE sample_entries SET {field}=?, updated_by=?, updated_at=? WHERE receipt_id=? AND row_num=? AND is_duplicate=?",
                (value, session['user_id'], datetime.now().isoformat(), rid, row, is_dup)
            )
        else:
            conn.execute(
                f"INSERT INTO sample_entries(receipt_id, row_num, is_duplicate, {field}, updated_by, updated_at) VALUES(?,?,?,?,?,?)",
                (rid, row, is_dup, value, session['user_id'], datetime.now().isoformat())
            )
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/analysis/autosave/calc', methods=['POST'])
@lab_required
def analysis_autosave_calc():
    """Тооцоолсон үр дүнг хадгална"""
    try:
        data = request.get_json()
        rid    = data.get('receipt_id')
        row    = data.get('row_num')
        is_dup = data.get('is_duplicate', 0)
        mad    = data.get('mad')
        aad    = data.get('aad')
        vad    = data.get('vad')
        fc     = data.get('fc')

        conn = get_db()
        conn.execute("""
            UPDATE sample_entries SET mad=?, aad=?, vad=?, fc=?, updated_at=?
            WHERE receipt_id=? AND row_num=? AND is_duplicate=?
        """, (mad, aad, vad, fc, datetime.now().isoformat(), rid, row, is_dup))
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/analysis/load/<int:receipt_id>')
@lab_required
def analysis_load(receipt_id):
    """Хадгалагдсан өгөгдлийг ачаална"""
    conn = get_db()
    entries = conn.execute(
        "SELECT * FROM sample_entries WHERE receipt_id=? ORDER BY row_num, is_duplicate",
        (receipt_id,)
    ).fetchall()
    conn.close()
    result = {}
    for e in entries:
        key = f"{e['row_num']}_{e['is_duplicate']}"
        result[key] = dict(e)
    return jsonify(result)


@app.route('/analysis/prep/start/<int:receipt_id>', methods=['POST'])
@preparer_required
def prep_start(receipt_id):
    conn = get_db()
    conn.execute("""UPDATE sample_receipt SET prep_status='preparing', prep_started_at=?
                   WHERE id=?""", (datetime.now().isoformat(), receipt_id))
    conn.execute("UPDATE geo_samples SET status='preparing' WHERE id=(SELECT geo_sample_id FROM sample_receipt WHERE id=?)", (receipt_id,))
    conn.commit(); conn.close()
    flash('Дээж бэлтгэж эхэллээ!', 'success')
    return redirect(url_for('analysis'))

@app.route('/analysis/prep/done/<int:receipt_id>', methods=['POST'])
@preparer_required
def prep_done(receipt_id):
    conn = get_db()
    notes = request.form.get('notes','')
    prep_operator = request.form.get('prep_operator','').strip()
    prep_position = request.form.get('prep_position','').strip()
    prep_devices  = ', '.join(filter(None, request.form.getlist('prep_device')))
    conn.execute("""UPDATE sample_receipt
        SET prep_status='ready', prep_done_at=?, prep_notes=?,
            prep_operator=?, prep_position=?, prep_devices=?
        WHERE id=?""", (datetime.now().isoformat(), notes,
                        prep_operator, prep_position, prep_devices,
                        receipt_id))
    conn.execute("UPDATE geo_samples SET status='ready' WHERE id=(SELECT geo_sample_id FROM sample_receipt WHERE id=?)", (receipt_id,))
    lab_num = conn.execute('SELECT lab_number FROM sample_receipt WHERE id=?', (receipt_id,)).fetchone()
    lab_str = lab_num[0] if lab_num else ''
    conn.commit(); conn.close()
    flash(f'✅ Дээж бэлтгэж дууслаа! Химичид шилжлээ. Ажлын дугаар: {lab_str}', 'success')
    return redirect(url_for('analysis'))

# ── SAMPLE TYPES ────────────────────────────────────────

@app.route('/sample-types', methods=['GET','POST'])
@admin_required
def sample_types():
    lang = session.get('lang','mn')
    conn = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            conn.execute("""
                INSERT INTO sample_types(code,name_mn,name_en,icon,color,serial_from,serial_to,is_pit,sort_order)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (
                request.form['code'].upper().strip(),
                request.form['name_mn'],
                request.form.get('name_en',''),
                request.form.get('icon','🧪'),
                request.form.get('color','#185fa5'),
                int(request.form.get('serial_from') or 7000),
                int(request.form.get('serial_to') or 7999),
                1 if request.form.get('is_pit') else 0,
                int(request.form.get('sort_order') or 99)
            ))
            flash('Дээжний төрөл нэмэгдлээ!', 'success')
        elif action == 'toggle':
            tid = request.form.get('id')
            conn.execute("UPDATE sample_types SET is_active=1-is_active WHERE id=?", (tid,))
            flash('Өөрчлөгдлөө!', 'success')
        elif action == 'delete':
            tid = request.form.get('id')
            conn.execute("DELETE FROM sample_types WHERE id=?", (tid,))
            flash('Устгагдлаа!', 'success')
        conn.commit()
        conn.close()
        return redirect(url_for('lab_settings') + '?tab=types')
    
    types = conn.execute("SELECT * FROM sample_types ORDER BY sort_order, serial_from").fetchall()
    conn.close()
    return jsonify([dict(t) for t in types])


@app.route('/analysis/row/done', methods=['POST'])
@lab_required
def row_done():
    """Химич мөрийг дууслаа гэж тэмдэглэнэ"""
    data = request.get_json()
    rid = data.get('receipt_id')
    row = data.get('row_num')
    dup = data.get('is_duplicate', 0)
    conn = get_db()
    # Мөр байгаа эсэх
    existing = conn.execute(
        "SELECT id FROM sample_entries WHERE receipt_id=? AND row_num=? AND is_duplicate=?",
        (rid, row, dup)
    ).fetchone()
    if existing:
        conn.execute("""UPDATE sample_entries SET row_status='done', done_by=?, done_at=?
                       WHERE receipt_id=? AND row_num=? AND is_duplicate=?""",
                    (session['user_id'], datetime.now().isoformat(), rid, row, dup))
    else:
        conn.execute("""INSERT INTO sample_entries(receipt_id,row_num,is_duplicate,row_status,done_by,done_at)
                       VALUES(?,?,?,'done',?,?)""",
                    (rid, row, dup, session['user_id'], datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/analysis/row/done-all', methods=['POST'])
@lab_required
def row_done_all():
    """Бүх мөрийг нэгэн зэрэг done/undo хийнэ"""
    data = request.get_json()
    rid = data.get('receipt_id')
    rows = data.get('rows', [])
    conn = get_db()
    for r in rows:
        row = r.get('row_num')
        dup = r.get('is_duplicate', 0)
        action = r.get('action', 'done')
        if action == 'done':
            existing = conn.execute(
                "SELECT id FROM sample_entries WHERE receipt_id=? AND row_num=? AND is_duplicate=?",
                (rid, row, dup)
            ).fetchone()
            if existing:
                conn.execute("""UPDATE sample_entries SET row_status='done', done_by=?, done_at=?
                               WHERE receipt_id=? AND row_num=? AND is_duplicate=?""",
                            (session['user_id'], datetime.now().isoformat(), rid, row, dup))
            else:
                conn.execute("""INSERT INTO sample_entries(receipt_id,row_num,is_duplicate,row_status,done_by,done_at)
                               VALUES(?,?,?,'done',?,?)""",
                            (rid, row, dup, session['user_id'], datetime.now().isoformat()))
        else:
            conn.execute("""UPDATE sample_entries SET row_status='empty', done_by=NULL, done_at=NULL
                           WHERE receipt_id=? AND row_num=? AND is_duplicate=?""",
                        (rid, row, dup))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/analysis/row/approve', methods=['POST'])
@senior_required
def row_approve():
    """Ахлах химич мөрийг баталгаажуулна"""
    data = request.get_json()
    rid = data.get('receipt_id')
    rows = data.get('rows', [])  # [{row_num, is_duplicate}]
    approve_all = data.get('approve_all', False)
    conn = get_db()
    if approve_all:
        conn.execute("""UPDATE sample_entries SET row_status='approved', approved_by=?, approved_at=?
                       WHERE receipt_id=? AND row_status='done'""",
                    (session['user_id'], datetime.now().isoformat(), rid))
    else:
        for r in rows:
            conn.execute("""UPDATE sample_entries SET row_status='approved', approved_by=?, approved_at=?
                           WHERE receipt_id=? AND row_num=? AND is_duplicate=?""",
                        (session['user_id'], datetime.now().isoformat(), rid, r['row_num'], r['is_duplicate']))
    conn.commit()
    # Бүх үндсэн мөр баталгаажсан эсэхийг шалгана
    total = conn.execute("SELECT COUNT(*) FROM sample_entries WHERE receipt_id=? AND is_duplicate=0", (rid,)).fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM sample_entries WHERE receipt_id=? AND is_duplicate=0 AND row_status='approved'", (rid,)).fetchone()[0]
    if total > 0 and total == approved:
        conn.execute("UPDATE geo_samples SET status='done' WHERE id=(SELECT geo_sample_id FROM sample_receipt WHERE id=?)", (rid,))
        conn.execute("UPDATE sample_receipt SET prep_status='done' WHERE id=?", (rid,))
        # Энэ receipt QC ажил байвал internal_qc.status='done' болгоно
        conn.execute("UPDATE internal_qc SET status='done' WHERE receipt_id_1=? AND status='pending'", (rid,))
        conn.commit()
    all_approved = (total > 0 and total == approved)
    conn.close()
    return jsonify({'ok': True, 'all_approved': all_approved})

@app.route('/analysis/result/<int:receipt_id>')
@login_required
def analysis_result(receipt_id):
    """Үр дүнгийн хуудас — бүх эрхэд харагдана"""
    lang = session.get('lang','mn')
    role = session.get('role')
    conn = get_db()
    # Баяжуулах эрхтэй: зөвхөн 6000-6999 + can_view_result=1 байвал харна
    if role == 'bayjuulach':
        u = conn.execute("SELECT can_view_result FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not u or not u['can_view_result']:
            conn.close()
            flash('Үр дүн харах эрх байхгүй байна', 'error')
            return redirect(url_for('dashboard'))
        sr = conn.execute("SELECT lab_serial FROM sample_receipt WHERE id=?", (receipt_id,)).fetchone()
        if not sr or not (6000 <= (sr['lab_serial'] or 0) <= 6999):
            conn.close()
            flash('Энэ ажлыг харах эрх байхгүй байна', 'error')
            return redirect(url_for('dashboard'))
        conn.execute("INSERT INTO result_view_log(user_id, receipt_id) VALUES(?,?)",
                     (session['user_id'], receipt_id))
        conn.commit()
    elif role == 'geologist':
        conn.execute("INSERT INTO result_view_log(user_id, receipt_id) VALUES(?,?)",
                     (session['user_id'], receipt_id))
        conn.commit()
    receipt = conn.execute("""
        SELECT sr.*, g.sample_name, g.sample_type, g.location,
               g.collected_date, g.quantity,
               ug.name as geo_name, up.name as prep_name
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        LEFT JOIN users ug ON ug.id=g.registered_by
        LEFT JOIN users up ON up.id=sr.received_by
        WHERE sr.id=?
    """, (receipt_id,)).fetchone()
    
    entries = conn.execute("""
        SELECT se.*, u1.name as done_name, u2.name as approved_name
        FROM sample_entries se
        LEFT JOIN users u1 ON u1.id=se.done_by
        LEFT JOIN users u2 ON u2.id=se.approved_by
        WHERE se.receipt_id=?
        ORDER BY se.row_num, se.is_duplicate
    """, (receipt_id,)).fetchall()

    crm_cert = None
    if receipt and receipt['sample_type'] == 'CRM':
        geo = conn.execute('SELECT crm_mad, crm_aad, crm_vad, crm_sulfur, crm_cal FROM geo_samples WHERE id=?',
                           (receipt['geo_sample_id'],)).fetchone()
        crm_cert = dict(geo) if geo else None

    conn.close()

    # mt_result тооцоолох + display_name үүсгэх
    import re as _re
    _sname = receipt['sample_name'] or '' if receipt else ''
    _sparts = [s.strip() for s in _sname.split(';')] if ';' in _sname else None
    _m1 = _re.match(r'^(.*?)(\d+)\s*[-–]\s*(\d+)\s*$', _sname)
    _m2 = _re.match(r'^(.*?)(\d+)$', _sname) if not _m1 else None
    entries_list = []
    for e in entries:
        ed = dict(e)
        try:
            mt_s = ed.get('mt_sample') or 0
            mt_t = ed.get('mt_tare') or 0
            mt_d = ed.get('mt_dried') or 0
            if mt_s and mt_s > 0:
                ed['mt_result'] = (mt_s - (mt_d - mt_t)) / mt_s * 100
            else:
                ed['mt_result'] = None
        except:
            ed['mt_result'] = None
        rn = ed.get('row_num', 1)
        en = ed.get('sample_name') or ''
        if en and en != _sname:
            ed['display_name'] = en
        elif _sparts and len(_sparts) >= rn:
            ed['display_name'] = _sparts[rn - 1]
        elif _m1:
            ed['display_name'] = _m1.group(1) + str(int(_m1.group(2)) + rn - 1)
        elif _m2:
            ed['display_name'] = _m2.group(1) + str(int(_m2.group(2)) + rn - 1)
        else:
            ed['display_name'] = _sname
        entries_list.append(ed)

    qc_row = request.args.get('qc_row', type=int)
    qc_id = request.args.get('qc_id', type=int)
    if qc_row:
        entries_list = [e for e in entries_list if e['row_num'] == qc_row]
    pending_approve = [e for e in entries_list if e['row_status'] == 'done' and e['is_duplicate'] == 0]
    return render_template('analysis/result.html',
        receipt=receipt, entries=entries_list, lang=lang, role=role, crm_cert=crm_cert,
        pending_approve=pending_approve, qc_row=qc_row, qc_id=qc_id)


@app.route('/analysis/export/<int:receipt_id>')
@login_required
def analysis_export(receipt_id):
    import openpyxl
    from openpyxl.styles import Font, Alignment
    import io, os

    conn = get_db()
    receipt = conn.execute("""
        SELECT sr.*, g.sample_name, g.sample_type, g.location,
               g.collected_date, g.quantity,
               ug.name as geo_name, up.name as prep_name
        FROM sample_receipt sr
        JOIN geo_samples g ON g.id=sr.geo_sample_id
        LEFT JOIN users ug ON ug.id=g.registered_by
        LEFT JOIN users up ON up.id=sr.received_by
        WHERE sr.id=?
    """, (receipt_id,)).fetchone()
    entries = conn.execute("""
        SELECT * FROM sample_entries WHERE receipt_id=? ORDER BY row_num, is_duplicate
    """, (receipt_id,)).fetchall()
    conn.close()

    # Template ачаалах
    tmpl = os.path.join(os.path.dirname(__file__), 'static', 'report_template.xlsx')
    wb = openpyxl.load_workbook(tmpl)
    ws = wb.worksheets[0]

    # ── Мэдээлэл нөхөх ──────────────────────────────────────
    TYPE_DISPLAY = {
        'PIT':'Уурхай\nPIT','STOCKPILE':'Овоолго\nStockpile','EXPORT':'Экспорт\nExport',
        'CONTROL':'Гааль\nControl','EQ_CONTROL':'Гадаад хяналт\nEQ control','DP':'Баяжуулах\nDP',
    }

    # A9: гарчигт лаб дугаар нэмэх
    ws['A9'] = f" СОРИЛТЫН ҮР ДҮНГИЙН ТАЙЛАН №   {receipt['lab_number']}"

    # C12: лаб дугаар
    ws['C12'] = receipt['lab_number']

    # H12: хүлээн авсан огноо
    ws['H12'] = receipt['received_date'] or ''

    # C13: дээжний төрөл
    ws['C13'] = TYPE_DISPLAY.get(receipt['sample_type'], receipt['sample_type'])

    # H13: шинжилгээ хийсэн огноо
    analysed = receipt['prep_done_at'] or ''
    if analysed and 'T' in str(analysed):
        analysed = str(analysed).split('T')[0]
    ws['H13'] = analysed

    # H14: тайлан хэвлэсэн огноо
    ws['H14'] = datetime.now().strftime('%Y-%m-%d')

    # ── Өгөгдлийн мөрүүд (20-р мөрөөс) ─────────────────────
    row_map = {(e['row_num'], e['is_duplicate']): e for e in entries}

    def safe(e, field, dec=None):
        try:
            v = e[field]
            if v is None:
                return None
            return round(float(v), dec) if dec is not None else v
        except Exception:
            return None

    def calc_mt(e):
        fs = safe(e, 'ff_sample')
        fd = safe(e, 'ff_dried')
        if fs and fs > 0 and fd is not None:
            return round((fs - fd) / fs * 100, 2)
        return None

    def calc_g(e):
        try:
            if e['g_val'] is not None:
                return round(float(e['g_val']), 1)
            gc = safe(e,'g_coke'); gt = safe(e,'g_tare')
            gs1 = safe(e,'g_sieve1'); gs2 = safe(e,'g_sieve2')
            if gc is not None and gt is not None and gs1 is not None and gs2 is not None:
                d = gc - gt
                if d > 0:
                    return round((gs1 + gs2) / d * 100, 1)
        except Exception:
            pass
        return None

    data_row = 20
    for ri in range(1, (receipt['quantity'] or 1) + 1):
        e  = row_map.get((ri, 0))
        de = row_map.get((ri, 1))

        ws.cell(data_row, 1,  ri)
        ws.cell(data_row, 2,  safe(e,'sample_name') or f'Дээж {ri}')
        ws.cell(data_row, 3,  safe(e,'mass_kg', 3))
        ws.cell(data_row, 4,  calc_mt(e))
        ws.cell(data_row, 5,  safe(e,'mad', 2))
        ws.cell(data_row, 6,  safe(e,'aad', 2))
        # col 7 (Adb) - хоосон
        ws.cell(data_row, 8,  safe(e,'vad', 2))
        # col 9 (Vdb), 10 (Vdaf) - хоосон
        ws.cell(data_row, 11, safe(e,'fc', 2))
        ws.cell(data_row, 12, safe(e,'sulfur', 3))
        # col 13 (Sdb) - хоосон
        ws.cell(data_row, 14, safe(e,'cal_value', 0))
        # col 15 (Qnet,ar) - хоосон
        ws.cell(data_row, 16, calc_g(e))
        ws.cell(data_row, 17, safe(e,'fsi', 1))
        data_row += 1


    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    fname = f"result_{receipt['lab_number']}_{datetime.now().strftime('%Y%m%d')}.xlsx"
    return send_file(output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True, download_name=fname)


# ── DEVICE USAGE ─────────────────────────────────────────

@app.route('/analysis/device-map', methods=['GET','POST'])
@admin_required
def device_map():
    """Шинжилгээний төрөл → тоног холбоос тохируулах"""
    conn = get_db()
    if request.method == 'POST':
        analysis_type = request.form.get('analysis_type')
        device_id = request.form.get('device_id')
        # Хуучин устгаад шинэ нэмэх
        conn.execute("DELETE FROM analysis_device_map WHERE analysis_type=?", (analysis_type,))
        if device_id:
            conn.execute("""INSERT INTO analysis_device_map(analysis_type, device_id, updated_by, updated_at)
                           VALUES(?,?,?,?)""",
                        (analysis_type, device_id, session['user_id'], datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    
    devices = conn.execute("SELECT * FROM devices WHERE status='active' AND (stage='analysis' OR stage='both' OR stage IS NULL) ORDER BY name").fetchall()
    mapping = {r['analysis_type']: r['device_id'] for r in
               conn.execute("SELECT * FROM analysis_device_map WHERE is_active=1").fetchall()}
    conn.close()
    return jsonify({'devices': [dict(d) for d in devices], 'mapping': mapping})

@app.route('/analysis/device-usage/start', methods=['POST'])
@login_required
def device_usage_start():
    """Химич шинжилгээ эхлэхэд тоногийн ашиглалт бүртгэнэ"""
    data = request.get_json()
    device_id = data.get('device_id')
    receipt_id = data.get('receipt_id')
    analysis_type = data.get('analysis_type')
    if not device_id:
        return jsonify({'ok': False})
    conn = get_db()
    # Хэрэв аль хэдийн нээлттэй байвал хаах
    conn.execute("""UPDATE device_usage_log 
                   SET ended_at=?, duration_min=ROUND((JULIANDAY(?)-JULIANDAY(started_at))*1440,1)
                   WHERE user_id=? AND device_id=? AND ended_at IS NULL""",
                (datetime.now().isoformat(), datetime.now().isoformat(),
                 session['user_id'], device_id))
    # Шинэ нээх
    cur = conn.execute("""INSERT INTO device_usage_log(device_id, user_id, receipt_id, analysis_type, started_at)
                          VALUES(?,?,?,?,?)""",
                      (device_id, session['user_id'], receipt_id, analysis_type, 
                       datetime.now().isoformat()))
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'log_id': log_id})

@app.route('/analysis/device-usage/end', methods=['POST'])
@login_required  
def device_usage_end():
    """Химич дуусгахад тоногийн ашиглалт хаана"""
    data = request.get_json()
    device_id = data.get('device_id')
    sample_count = data.get('sample_count', 0)
    now = datetime.now().isoformat()
    conn = get_db()
    conn.execute("""UPDATE device_usage_log 
                   SET ended_at=?, sample_count=?,
                       duration_min=ROUND((JULIANDAY(?)-JULIANDAY(started_at))*1440,1)
                   WHERE user_id=? AND device_id=? AND ended_at IS NULL""",
                (now, sample_count, now, session['user_id'], device_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/analysis/device-usage/end-session', methods=['POST'])
@login_required
def device_usage_end_session():
    """Гарах үед бүх нээлттэй ашиглалтыг хаана"""
    now = datetime.now().isoformat()
    conn = get_db()
    conn.execute("""UPDATE device_usage_log
                   SET ended_at=?,
                       duration_min=ROUND((JULIANDAY(?)-JULIANDAY(started_at))*1440,1)
                   WHERE user_id=? AND ended_at IS NULL""",
                (now, now, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/analysis/measure/multi', methods=['GET','POST'])
@lab_required
def analysis_measure_multi():
    """Олон lot-ыг нэг хуудсанд нэгтгэх"""
    lang = session.get('lang','mn')
    conn = get_db()
    
    if request.method == 'POST':
        # Сонгосон receipt_ids авах
        ids = request.form.getlist('receipt_ids')
        if not ids:
            flash('Дор хаяж нэг ажлын дугаар сонгоно уу!', 'error')
            return redirect(url_for('analysis'))
        return redirect(url_for('analysis_measure_multi') + '?ids=' + ','.join(ids))
    
    # GET — ids параметрээс авах
    ids_str = request.args.get('ids','')
    if not ids_str:
        return redirect(url_for('analysis'))

    ids = [int(i) for i in ids_str.split(',') if i.strip().isdigit()]

    # qc_rows параметр: "rid1:rn1,rid2:rn2" — зөвхөн тодорхой мөрийг харуулах
    qc_rows_str = request.args.get('qc_rows','')
    qc_row_map = {}  # {receipt_id: row_num}
    if qc_rows_str:
        for part in qc_rows_str.split(','):
            if ':' in part:
                r, n = part.split(':', 1)
                if r.strip().isdigit() and n.strip().isdigit():
                    qc_row_map[int(r.strip())] = int(n.strip())

    receipts = []
    for rid in ids:
        r = conn.execute("""
            SELECT sr.*, g.sample_name, g.sample_type, g.location,
                   g.collected_date, g.quantity,
                   ug.name as geo_name, up.name as prep_name
            FROM sample_receipt sr
            JOIN geo_samples g ON g.id=sr.geo_sample_id
            LEFT JOIN users ug ON ug.id=g.registered_by
            LEFT JOIN users up ON up.id=sr.received_by
            WHERE sr.id=?
        """, (rid,)).fetchone()
        if r:
            receipts.append(r)

    conn.close()
    if not receipts:
        return redirect(url_for('analysis'))

    qc_receipt_ids = [str(k) for k in qc_row_map.keys()]
    qc_id = request.args.get('qc_id', type=int)
    return render_template('analysis/measure_multi.html',
        receipts=receipts, lang=lang,
        ids=ids_str, qc_row_map=qc_row_map, qc_receipt_ids=qc_receipt_ids, qc_id=qc_id)

# ── LAB SETTINGS ────────────────────────────────────────
import json as _json

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'settings.json')

def get_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, encoding='utf-8') as f:
            return _json.load(f)
    return {'lab_name':'Лабораторийн нэр','lab_name_en':'Laboratory','lab_subtitle':'Лабораторийн удирдлагын систем','logo':'logo.jpg'}

def save_settings(data):
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        _json.dump(data, f, ensure_ascii=False, indent=2)

@app.context_processor
def inject_settings():
    return dict(settings=get_settings())

@app.route('/lab-settings', methods=['GET','POST'])
@admin_required
def lab_settings():
    lang = session.get('lang','mn')
    s = get_settings()
    conn = get_db()
    qc_settings_list = conn.execute("SELECT * FROM qc_settings ORDER BY parameter").fetchall()

    if request.method == 'POST':
        action = request.form.get('action','lab_info')

        if action == 'lab_info':
            s['lab_name']     = request.form.get('lab_name', s['lab_name'])
            s['lab_name_en']  = request.form.get('lab_name_en', s['lab_name_en'])
            s['lab_subtitle'] = request.form.get('lab_subtitle', s['lab_subtitle'])
            logo = request.files.get('logo')
            if logo and logo.filename:
                ext = logo.filename.rsplit('.',1)[-1].lower()
                if ext in ('png','jpg','jpeg','webp'):
                    logo.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', f'logo.{ext}'))
                    s['logo'] = f'logo.{ext}'
            save_settings(s)
            flash('Лабораторийн мэдээлэл хадгалагдлаа!', 'success')

        elif action == 'qc_settings':
            for q in qc_settings_list:
                key = f"tol_{q['parameter']}"
                val = request.form.get(key)
                if val:
                    conn.execute("UPDATE qc_settings SET tolerance=?, updated_by=? WHERE parameter=?",
                                (float(val), session['user_id'], q['parameter']))
            conn.commit()
            flash('QC тохиргоо хадгалагдлаа!', 'success')

        elif action == 'update_profile':
            photo = save_file(request.files.get('photo'), 'staff')
            conn.execute("UPDATE users SET position=?, phone=?, email=? WHERE id=?", (
                request.form.get('position'),
                request.form.get('phone'),
                request.form.get('email'),
                session['user_id']
            ))
            if photo:
                conn.execute("UPDATE users SET photo=? WHERE id=?", (photo, session['user_id']))
            conn.commit()
            flash('Профайл шинэчлэгдлээ!', 'success')

        elif action == 'change_password':
            user = conn.execute("SELECT * FROM users WHERE id=?", (session.get('user_id', 0),)).fetchone()
            old_pw = request.form.get('old_password','')
            new_pw = request.form.get('new_password','')
            confirm = request.form.get('confirm_password','')
            if not check_password(user['password_hash'], old_pw):
                flash('Хуучин нууц үг буруу!', 'error')
            elif new_pw != confirm:
                flash('Шинэ нууц үг таарахгүй байна!', 'error')
            elif len(new_pw) < 6:
                flash('Нууц үг хамгийн багадаа 6 тэмдэгт!', 'error')
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (hash_password(new_pw), session['user_id']))
                conn.commit()
                flash('Нууц үг амжилттай солигдлоо!', 'success')

        conn.close()
        return redirect(url_for('lab_settings'))

    conn.close()
    _crm_conn = get_db()
    crm_materials = _crm_conn.execute("SELECT * FROM crm_materials ORDER BY crm_name").fetchall()
    now = datetime.now().isoformat()
    _crm_conn.execute("DELETE FROM guest_tokens WHERE expires_at < ?", (now,))
    _crm_conn.commit()
    guest_tokens = _crm_conn.execute("SELECT * FROM guest_tokens ORDER BY created_at DESC").fetchall()
    _crm_conn.close()
    return render_template('admin/settings.html', s=s, qc_settings=qc_settings_list, lang=lang,
                           crm_materials=crm_materials, today=date.today().isoformat(),
                           guest_tokens=guest_tokens, now=now)

@app.route('/lab-settings/crm', methods=['POST'])
@admin_required
def lab_settings_crm():
    action = request.form.get('action')
    conn = get_db()
    try:
        if action == 'add':
            name = request.form.get('crm_name', '').strip()
            if not name:
                flash('CRM нэрийг оруулна уу', 'error')
                return redirect(url_for('lab_settings') + '?tab=crm')
            conn.execute("""INSERT INTO crm_materials (crm_name, aad_cert, aad_unc, vad_cert, vad_unc, sulfur_cert, sulfur_unc, cal_cert, cal_unc, g_cert, g_unc, notes, standard, manufacture_date, expiry_date, open_date)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                name,
                request.form.get('aad_cert') or None,
                request.form.get('aad_unc') or None,
                request.form.get('vad_cert') or None,
                request.form.get('vad_unc') or None,
                request.form.get('sulfur_cert') or None,
                request.form.get('sulfur_unc') or None,
                request.form.get('cal_cert') or None,
                request.form.get('cal_unc') or None,
                request.form.get('g_cert') or None,
                request.form.get('g_unc') or None,
                request.form.get('notes', '').strip() or None,
                request.form.get('standard', '').strip() or None,
                request.form.get('manufacture_date') or None,
                request.form.get('expiry_date') or None,
                request.form.get('open_date') or None,
            ))
            conn.commit()
            flash(f'CRM материал нэмэгдлээ: {name}', 'success')
        elif action == 'delete':
            mid = request.form.get('id')
            conn.execute("DELETE FROM crm_materials WHERE id=?", (mid,))
            conn.commit()
            flash('CRM материал устгагдлаа', 'success')
        elif action == 'deactivate':
            mid = request.form.get('id')
            conn.execute("UPDATE crm_materials SET is_active=0 WHERE id=?", (mid,))
            conn.commit()
            flash('CRM материал дуусгагдлаа', 'success')
    finally:
        conn.close()
    return redirect(url_for('lab_settings') + '?tab=crm')

@app.route('/lab-settings/crm/<int:mid>/edit', methods=['GET','POST'])
@admin_required
def crm_edit(mid):
    conn = get_db()
    mat = conn.execute("SELECT * FROM crm_materials WHERE id=?", (mid,)).fetchone()
    if not mat:
        conn.close()
        flash('CRM материал олдсонгүй', 'error')
        return redirect(url_for('lab_settings') + '?tab=crm')
    if request.method == 'POST':
        conn.execute("""UPDATE crm_materials SET
            crm_name=?, aad_cert=?, aad_unc=?, vad_cert=?, vad_unc=?,
            sulfur_cert=?, sulfur_unc=?, cal_cert=?, cal_unc=?,
            g_cert=?, g_unc=?, notes=?, standard=?,
            manufacture_date=?, expiry_date=?, open_date=?
            WHERE id=?""", (
            request.form.get('crm_name','').strip(),
            request.form.get('aad_cert') or None, request.form.get('aad_unc') or None,
            request.form.get('vad_cert') or None, request.form.get('vad_unc') or None,
            request.form.get('sulfur_cert') or None, request.form.get('sulfur_unc') or None,
            request.form.get('cal_cert') or None, request.form.get('cal_unc') or None,
            request.form.get('g_cert') or None, request.form.get('g_unc') or None,
            request.form.get('notes','').strip() or None,
            request.form.get('standard','').strip() or None,
            request.form.get('manufacture_date') or None,
            request.form.get('expiry_date') or None,
            request.form.get('open_date') or None,
            mid
        ))
        conn.commit(); conn.close()
        flash('CRM материал шинэчлэгдлээ', 'success')
        return redirect(url_for('lab_settings') + '?tab=crm')
    conn.close()
    return render_template('admin/crm_edit.html', mat=mat, today=date.today().isoformat())

@app.route('/backup')
@admin_required
def backup_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'lab.db')
    from datetime import datetime as dt
    fname = f"lab_backup_{dt.now().strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(db_path, as_attachment=True, download_name=fname)

# ── ШАЛГАЛТЫН ЗАГВАР (check templates) ──────────────────
@app.route('/check-templates')
@login_required
def check_templates_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM check_templates ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/check-templates/add', methods=['POST'])
@senior_required
def check_templates_add():
    conn = get_db()
    data = request.get_json()
    conn.execute("""INSERT INTO check_templates
        (name,param1,standard1,tolerance1,param2,standard2,tolerance2,
         param3,standard3,tolerance3,param4,standard4,tolerance4,created_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        data.get('name'), data.get('param1'), data.get('standard1'), data.get('tolerance1'),
        data.get('param2'), data.get('standard2'), data.get('tolerance2'),
        data.get('param3'), data.get('standard3'), data.get('tolerance3'),
        data.get('param4'), data.get('standard4'), data.get('tolerance4'),
        session.get('user_id')
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/check-templates/<int:tid>/delete', methods=['POST'])
@senior_required
def check_templates_delete(tid):
    conn = get_db()
    conn.execute("DELETE FROM check_templates WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/backup/list')
@admin_required
def backup_list():
    import glob, os
    inst = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    files = []
    for f in sorted(glob.glob(os.path.join(inst, 'lab_backup_*.db')), reverse=True):
        stat = os.stat(f)
        files.append({
            'name': os.path.basename(f),
            'size': stat.st_size,
            'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
        })
    return jsonify(files)

@app.route('/backup/download/<filename>')
@admin_required
def backup_download(filename):
    import re
    if not re.match(r'^lab_backup_[\d_]+\.db$', filename):
        return 'Invalid', 400
    inst = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    path = os.path.join(inst, filename)
    if not os.path.exists(path):
        return 'Not found', 404
    return send_file(path, as_attachment=True, download_name=filename)

@app.route('/backup/create', methods=['POST'])
@admin_required
def backup_create():
    import shutil
    from datetime import datetime as dt
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'lab.db')
    bk_name = f"lab_backup_{dt.now().strftime('%Y%m%d_%H%M%S')}.db"
    bk_path = os.path.join(os.path.dirname(db_path), bk_name)
    shutil.copy2(db_path, bk_path)
    return jsonify({'ok': True, 'name': bk_name})

@app.route('/backup/delete/<filename>', methods=['POST'])
@admin_required
def backup_delete(filename):
    import re
    if not re.match(r'^lab_backup_[\d_]+\.db$', filename):
        return jsonify({'ok': False}), 400
    inst = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    path = os.path.join(inst, filename)
    if os.path.exists(path):
        os.remove(path)
    return jsonify({'ok': True})


def _startup():
    init_db()
    from models import init_analysis_db
    init_analysis_db()
    ensure_tables()

_startup()

if __name__ == '__main__':
    # Автомат backup
    import shutil
    _db = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'lab.db')
    _bk = _db.replace('lab.db', f'lab_backup_{datetime.now().strftime("%Y%m%d")}.db')
    if os.path.exists(_db) and not os.path.exists(_bk):
        shutil.copy2(_db, _bk)
        print(f'Backup: {_bk}')
    print('Систем эхэллээ!')
    print('Браузерт нэвтрэх: http://localhost:5000')
    app.run(debug=False, host='0.0.0.0', port=5000)
