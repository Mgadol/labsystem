from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from models import get_db, init_db, hash_password, check_password
from datetime import datetime, date
from functools import wraps
import os, uuid, io
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'lab-secret-2024'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED = {'png','jpg','jpeg','gif','webp','pdf','doc','docx'}

def allowed(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED

def save_file(file, subfolder):
    if file and file.filename and allowed(file.filename):
        ext  = file.filename.rsplit('.',1)[1].lower()
        name = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(path, exist_ok=True)
        file.save(os.path.join(path, name))
        return f"{subfolder}/{name}"
    return None

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
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
    if 'user_id' in session:
        user = get_user(session['user_id'])
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
        emp_id = request.form.get('employee_id','').strip()
        pw     = request.form.get('password','')
        conn   = get_db()
        u = conn.execute("SELECT * FROM users WHERE employee_id=? AND is_active=1",(emp_id,)).fetchone()
        conn.close()
        if u and check_password(u['password_hash'], pw):
            session['user_id'] = u['id']
            session['role']    = u['role']
            return redirect(url_for('dashboard'))
        error = 'Нэвтрэх нэр эсвэл нууц үг буруу.' if lang=='mn' else 'Invalid ID or password.'
    return render_template('auth/login.html', error=error, lang=lang)

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
    if session.get('role') == 'admin':
        devices  = conn.execute("SELECT d.*, dm.manufacturer, dm.model FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id ORDER BY d.name").fetchall()
        users    = conn.execute("SELECT * FROM users WHERE is_active=1").fetchall()
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
        conn.close()
        return render_template('admin/dashboard.html',
            devices=devices, users=users, open_rep=open_rep, expiring=expiring, lang=lang)
    else:
        uid = session['user_id']
        my_devices = conn.execute("""
            SELECT d.*, dm.manufacturer, dm.model FROM devices d
            LEFT JOIN device_marks dm ON d.mark_id=dm.id
            JOIN staff_device_permissions p ON p.device_id=d.id
            WHERE p.user_id=? ORDER BY d.name
        """, (uid,)).fetchall()
        active_log = conn.execute("SELECT * FROM usage_logs WHERE user_id=? AND end_time IS NULL", (uid,)).fetchone()
        conn.close()
        return render_template('staff/dashboard.html',
            devices=my_devices, active_log=active_log, lang=lang)

# ── DEVICES ─────────────────────────────────────────────
@app.route('/devices')
@login_required
def devices():
    lang = session.get('lang','mn')
    conn = get_db()
    if session.get('role') == 'admin':
        devs = conn.execute("SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id ORDER BY d.name").fetchall()
    else:
        devs = conn.execute("""
            SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d
            LEFT JOIN device_marks dm ON d.mark_id=dm.id
            JOIN staff_device_permissions p ON p.device_id=d.id
            WHERE p.user_id=? ORDER BY d.name
        """, (session['user_id'],)).fetchall()
    conn.close()
    return render_template('device/list.html', devices=devs, lang=lang)

@app.route('/devices/<int:did>')
@login_required
def device_detail(did):
    lang = session.get('lang','mn')
    conn = get_db()
    device = conn.execute("SELECT d.*, dm.manufacturer, dm.model, dm.category FROM devices d LEFT JOIN device_marks dm ON d.mark_id=dm.id WHERE d.id=?", (did,)).fetchone()
    if not device:
        conn.close(); return redirect(url_for('devices'))
    if session.get('role') != 'admin':
        perm = conn.execute("SELECT 1 FROM staff_device_permissions WHERE user_id=? AND device_id=?", (session['user_id'], did)).fetchone()
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
    conn.close()
    return render_template('device/detail.html',
        device=device, calibrations=cals, repairs=reps,
        usage_logs=logs, active_log=active,
        monthly_hours=round(mhours,2),
        lang=lang, today=date.today().isoformat())

@app.route('/devices/add', methods=['GET','POST'])
@senior_required
def device_add():
    lang = session.get('lang','mn')
    conn = get_db()
    marks = conn.execute("SELECT * FROM device_marks ORDER BY manufacturer").fetchall()
    if request.method == 'POST':
        photo = save_file(request.files.get('photo'), 'devices')
        pdf   = save_file(request.files.get('passport_pdf'), 'passports')
        conn.execute("""
            INSERT INTO devices(name,serial_number,mark_id,location,purchase_date,
            warranty_expiry,calibration_interval,photo,passport_pdf,status,notes)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            request.form['name'],
            request.form.get('serial_number') or None,
            request.form.get('mark_id') or None,
            request.form.get('location'),
            request.form.get('purchase_date') or None,
            request.form.get('warranty_expiry') or None,
            int(request.form.get('calibration_interval') or 90),
            photo, pdf, 'active',
            request.form.get('notes')
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
    device = conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    marks  = conn.execute("SELECT * FROM device_marks").fetchall()
    if request.method == 'POST':
        photo = save_file(request.files.get('photo'), 'devices')
        pdf   = save_file(request.files.get('passport_pdf'), 'passports')
        conn.execute("""
            UPDATE devices SET name=?,serial_number=?,mark_id=?,location=?,
            purchase_date=?,warranty_expiry=?,calibration_interval=?,
            status=?,notes=?
            WHERE id=?
        """, (
            request.form['name'],
            request.form.get('serial_number') or None,
            request.form.get('mark_id') or None,
            request.form.get('location'),
            request.form.get('purchase_date') or None,
            request.form.get('warranty_expiry') or None,
            int(request.form.get('calibration_interval') or 90),
            request.form.get('status','active'),
            request.form.get('notes'), did
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
    uid  = session['user_id']
    conn = get_db()
    if session.get('role') != 'admin':
        perm = conn.execute("SELECT 1 FROM staff_device_permissions WHERE user_id=? AND device_id=?", (uid, did)).fetchone()
        if not perm:
            conn.close(); return jsonify({'error': 'Эрх байхгүй'}), 403
    active = conn.execute("SELECT id FROM usage_logs WHERE user_id=? AND end_time IS NULL", (uid,)).fetchone()
    if active:
        conn.close(); return jsonify({'error': 'Та аль хэдийн өөр төхөөрөмж дээр ажиллаж байна!'}), 400
    now = datetime.now().isoformat()
    conn.execute("INSERT INTO usage_logs(device_id,user_id,start_time) VALUES(?,?,?)", (did, uid, now))
    lid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    return jsonify({'success': True, 'log_id': lid, 'start': now[11:16]})

@app.route('/usage/stop/<int:lid>', methods=['POST'])
@login_required
def usage_stop(lid):
    uid  = session['user_id']
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
    if status == 'new':
        conn.execute("UPDATE devices SET status='repair' WHERE id=?", (did,))
    conn.commit(); conn.close()
    flash('Засварын бүртгэл нэмэгдлээ!' if lang=='mn' else 'Repair added!', 'success')
    return redirect(url_for('device_detail', did=did))

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
@admin_required
def staff_list():
    lang = session.get('lang','mn')
    conn = get_db()
    users = conn.execute("SELECT * FROM users WHERE is_active=1 ORDER BY name").fetchall()
    conn.close()
    return render_template('admin/staff_list.html', users=users, lang=lang)

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
            conn.execute("""
                INSERT INTO users(employee_id,name,position,phone,email,photo,role,password_hash,joined_date)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (
                request.form['employee_id'], request.form['name'],
                request.form.get('position'), request.form.get('phone'),
                request.form.get('email'), photo,
                role_to_set, pw,
                request.form.get('joined_date') or None
            ))
            uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
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
    if session.get('role') != 'admin' and session['user_id'] != uid:
        return redirect(url_for('dashboard'))
    lang = session.get('lang','mn')
    conn = get_db()
    target  = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
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
    conn.close()
    return render_template('staff/detail.html', target=target, logs=logs, my_devices=my_devs, lang=lang)

# ── ARCHIVE ─────────────────────────────────────────────
@app.route('/archive')
@login_required
def archive():
    lang = session.get('lang','mn')
    conn = get_db()
    archived_devices = conn.execute("""
        SELECT d.*, dm.manufacturer, dm.model FROM devices d
        LEFT JOIN device_marks dm ON d.mark_id=dm.id
        WHERE d.status IN ('archived','replaced')
        ORDER BY d.name
    """).fetchall()
    archived_staff = conn.execute(
        "SELECT * FROM users WHERE is_active=0 ORDER BY name"
    ).fetchall()
    completed_repairs = conn.execute("""
        SELECT r.*, d.name as dname FROM repairs r
        LEFT JOIN devices d ON d.id=r.device_id
        WHERE r.status IN ('done','replaced')
        ORDER BY r.reported_date DESC
    """).fetchall()
    conn.close()
    return render_template('admin/archive.html',
        archived_devices=archived_devices,
        archived_staff=archived_staff,
        completed_repairs=completed_repairs,
        lang=lang)

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
            conn.execute("""
                UPDATE users SET name=?,position=?,phone=?,email=?,role=?,joined_date=?
                WHERE id=?
            """, (
                request.form.get('name', target['name']),
                request.form.get('position'),
                request.form.get('phone'),
                request.form.get('email'),
                role_to_set,
                request.form.get('joined_date') or None,
                uid
            ))
            if photo:
                conn.execute("UPDATE users SET photo=? WHERE id=?", (photo, uid))
            # Эрх шинэчлэх
            conn.execute("DELETE FROM staff_device_permissions WHERE user_id=?", (uid,))
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
    uid  = session['user_id']
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
    if uid == session['user_id']:
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

# ── DEVICE ARCHIVE / RESTORE ────────────────────────────
@app.route('/devices/<int:did>/archive', methods=['POST'])
@senior_required
def device_archive(did):
    lang = session.get('lang','mn')
    conn = get_db()
    reason = request.form.get('reason', 'archived')
    conn.execute("UPDATE devices SET status=? WHERE id=?", (reason, did))
    conn.commit(); conn.close()
    flash('Төхөөрөмж архивлагдлаа.' if lang=='mn' else 'Device archived.', 'success')
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

# ── REPORTS ─────────────────────────────────────────────
@app.route('/reports')
@senior_required
def reports():
    return render_template('admin/reports.html', lang=session.get('lang','mn'))

@app.route('/reports/export')
@senior_required
def report_export():
    rtype   = request.args.get('type', 'month')
    year    = int(request.args.get('year', datetime.now().year))
    month   = int(request.args.get('month', datetime.now().month))
    quarter = int(request.args.get('quarter', 1))
    half    = int(request.args.get('half', 1))

    if rtype == 'month':
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

    ym_list = ",".join([f"'{year}-{m:02d}'" for m in months])
    wu  = f"strftime('%Y-%m',ul.start_time) IN ({ym_list})"
    wc  = f"strftime('%Y-%m',c.calibration_date) IN ({ym_list})"
    wr  = f"strftime('%Y-%m',r.reported_date) IN ({ym_list})"
    wd  = f"strftime('%Y-%m',start_time) IN ({ym_list})"

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

    for ws in [ws1,ws2,ws3,ws4]:
        ws.page_setup.orientation='landscape'
        ws.page_setup.fitToPage=True; ws.page_setup.fitToWidth=1

    conn.close()
    buf=io.BytesIO(); wb.save(buf); buf.seek(0)
    fname=f'Лаборатори_{period_label.replace(' ','_')}.xlsx'
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
    uid = session['user_id']

    if role == 'geologist':
        samples = conn.execute("""
            SELECT g.*, u.name as reg_name,
                   sr.lab_number, sr.received_date, sr.mass_kg, sr.id as receipt_id, sr.prep_status
            FROM geo_samples g
            LEFT JOIN users u ON u.id=g.registered_by
            LEFT JOIN sample_receipt sr ON sr.geo_sample_id=g.id
            WHERE g.registered_by=? ORDER BY g.created_at DESC LIMIT 50
        """, (uid,)).fetchall()
    else:
        samples = conn.execute("""
            SELECT g.*, u.name as reg_name,
                   sr.lab_number, sr.received_date, sr.mass_kg, sr.id as receipt_id, sr.prep_status
            FROM geo_samples g
            LEFT JOIN users u ON u.id=g.registered_by
            LEFT JOIN sample_receipt sr ON sr.geo_sample_id=g.id
            ORDER BY g.created_at DESC LIMIT 200
        """).fetchall()
    conn.close()
    return render_template('analysis/index.html', samples=samples, lang=lang, today=datetime.now().strftime('%Y-%m-%d'))

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

        # PIT бол "1-100" хэлбэрийг задлах
        if sample_type == 'PIT':
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
                    registered_by, status, crm_name, crm_mad, crm_aad, crm_vad, crm_sulfur, crm_cal)
                VALUES (?, 'CRM', 'CRM', ?, 1, ?, ?, 'received', ?, ?, ?, ?, ?, ?)
            """, (crm_name, collected_date, notes, session['user_id'],
                  crm_name, mat['mad_cert'], mat['aad_cert'], mat['vad_cert'], mat['sulfur_cert'], mat['cal_cert']))
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
            flash(f'CRM дээж бүртгэгдлээ: {crm_name}', 'success')
            return redirect(url_for('analysis_measure', receipt_id=receipt_id))
        except Exception as e:
            conn.rollback()
            flash(f'Алдаа: {e}', 'error')
            return redirect(url_for('analysis_crm_register'))
        finally:
            conn.close()

    crm_materials = conn.execute("SELECT * FROM crm_materials WHERE is_active=1 ORDER BY crm_name").fetchall()
    conn.close()
    return render_template('analysis/crm_register.html', today=datetime.now().strftime('%Y-%m-%d'),
                           crm_materials=crm_materials)


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
    conn.close()
    return render_template('analysis/measure.html', receipt=receipt, lang=lang, today=datetime.now().strftime('%Y-%m-%d'))

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
    conn.execute("""UPDATE sample_receipt SET prep_status='ready', prep_done_at=?, prep_notes=?
                   WHERE id=?""", (datetime.now().isoformat(), notes, receipt_id))
    conn.execute("UPDATE geo_samples SET status='ready' WHERE id=(SELECT geo_sample_id FROM sample_receipt WHERE id=?)", (receipt_id,))
    lab_num = conn.execute('SELECT lab_number FROM sample_receipt WHERE id=?', (receipt_id,)).fetchone()
    lab_str = lab_num[0] if lab_num else ''
    conn.commit()
    conn.close()
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
                int(request.form.get('serial_from',7000)),
                int(request.form.get('serial_to',7999)),
                1 if request.form.get('is_pit') else 0,
                int(request.form.get('sort_order',99))
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

@app.route('/analysis/row/approve', methods=['POST'])
@senior_required
def row_approve():
    """Ахлах химич мөрийг баталгаажуулна"""
    data = request.get_json()
    rid = data.get('receipt_id')
    rows = data.get('rows', [])  # [{row_num, is_duplicate}]
    conn = get_db()
    for r in rows:
        conn.execute("""UPDATE sample_entries SET row_status='approved', approved_by=?, approved_at=?
                       WHERE receipt_id=? AND row_num=? AND is_duplicate=?""",
                    (session['user_id'], datetime.now().isoformat(), rid, r['row_num'], r['is_duplicate']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/analysis/result/<int:receipt_id>')
@login_required  
def analysis_result(receipt_id):
    """Үр дүнгийн хуудас — бүх эрхэд харагдана"""
    lang = session.get('lang','mn')
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

    role = session.get('role')
    return render_template('analysis/result.html',
        receipt=receipt, entries=entries, lang=lang, role=role, crm_cert=crm_cert)


@app.route('/analysis/export/<int:receipt_id>')
@login_required
def analysis_export(receipt_id):
    """Үр дүнг Excel файлаар татаж авах"""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import io

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
        SELECT * FROM sample_entries
        WHERE receipt_id=?
        ORDER BY row_num, is_duplicate
    """, (receipt_id,)).fetchall()
    conn.close()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Үр дүн"

    # Өнгө тодорхойлох
    hdr_fill = PatternFill("solid", fgColor="1E3A5F")
    hdr2_fill = PatternFill("solid", fgColor="2D5282")
    done_fill = PatternFill("solid", fgColor="FFF8F0")
    appr_fill = PatternFill("solid", fgColor="E6FFF8")
    dup_fill  = PatternFill("solid", fgColor="EEF5FF")
    hdr_font  = Font(bold=True, color="FFFFFF", size=10)
    hdr2_font = Font(color="BEE3F8", size=9)

    thin = Side(style='thin', color="D0D0C8")
    med  = Side(style='medium', color="555555")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    # 1-р мөр: Мэдээлэл
    ws.merge_cells('A1:M1')
    ws['A1'] = f"Ажлын дугаар: {receipt['lab_number']}  |  {receipt['sample_name']}  |  {receipt['sample_type']}  |  Огноо: {receipt['collected_date']}  |  Геологи: {receipt['geo_name'] or '—'}"
    ws['A1'].font = Font(bold=True, size=11, color="1E3A5F")
    ws.row_dimensions[1].height = 20

    # 2-р мөр: Толгой
    headers = ['No.', 'Дээжний нэр', 'Статус', 'Mt %', 'Mad %', 'Aad %', 'Vad %', 'FCad %', 'Sad %', 'Qb,ad J/g', 'G', 'CSN', 'Тэмдэглэл']
    for ci, h in enumerate(headers, 1):
        cell = ws.cell(2, ci, h)
        cell.fill = hdr_fill
        cell.font = hdr_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    ws.row_dimensions[2].height = 18

    # Өгөгдөл
    row_data = {}
    for e in entries:
        key = (e['row_num'], e['is_duplicate'])
        row_data[key] = e

    data_row = 3
    for ri in range(1, (receipt['quantity'] or 1) + 1):
        e  = row_data.get((ri, 0))
        de = row_data.get((ri, 1))
        is_done     = e and e['row_status'] in ('done','approved')
        is_approved = e and e['row_status'] == 'approved'

        fill = appr_fill if is_approved else (done_fill if is_done else PatternFill())

        vals = [
            ri,
            e['sample_name'] if e and e['sample_name'] else '—',
            '🟢 Баталгаажсан' if is_approved else ('🟠 Урьдчилсан' if is_done else '⬜ Хүлээгдэж байна'),
            None,  # Mt
            round(e['mad'], 4) if e and e['mad'] else None,
            round(e['aad'], 4) if e and e['aad'] else None,
            round(e['vad'], 4) if e and e['vad'] else None,
            round(e['fc'],  4) if e and e['fc']  else None,
            round(e['sulfur'], 3) if e and e['sulfur'] else None,
            round(e['cal_value'], 1) if e and e['cal_value'] else None,
            None,  # G
            round(e['fsi'], 1) if e and e['fsi'] else None,
            '',
        ]

        for ci, v in enumerate(vals, 1):
            cell = ws.cell(data_row, ci, v)
            cell.fill = fill
            cell.border = border
            cell.alignment = Alignment(horizontal='center' if ci != 2 else 'left', vertical='center')
            if ci >= 4 and v is not None:
                cell.number_format = '0.0000' if ci <= 8 else ('0.000' if ci == 9 else '0.0')
        ws.row_dimensions[data_row].height = 16
        data_row += 1

        # Зэрэгцээ мөр
        if de and de['row_status'] in ('done', 'approved'):
            dup_vals = [
                '', '↳ зэрэгцээ', '',
                None,
                round(de['mad'], 4) if de['mad'] else None,
                round(de['aad'], 4) if de['aad'] else None,
                round(de['vad'], 4) if de['vad'] else None,
                round(de['fc'],  4) if de['fc']  else None,
                round(de['sulfur'], 3) if de['sulfur'] else None,
                round(de['cal_value'], 1) if de['cal_value'] else None,
                None, None, '',
            ]
            for ci, v in enumerate(dup_vals, 1):
                cell = ws.cell(data_row, ci, v)
                cell.fill = dup_fill
                cell.border = border
                cell.alignment = Alignment(horizontal='center', vertical='center')
                if ci == 2:
                    cell.font = Font(italic=True, color="185FA5", size=9)
            ws.row_dimensions[data_row].height = 14
            data_row += 1

    # Баганы өргөн
    col_widths = [5, 20, 16, 8, 10, 10, 10, 10, 8, 12, 8, 8, 14]
    for ci, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(ci)].width = w

    # Freeze
    ws.freeze_panes = 'A3'

    # Excel файл буцаах
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    fname = f"result_{receipt['lab_number']}_{datetime.now().strftime('%Y%m%d')}.xlsx"
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=fname
    )


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
    
    devices = conn.execute("SELECT * FROM devices WHERE status='active' ORDER BY name").fetchall()
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
    
    return render_template('analysis/measure_multi.html', 
        receipts=receipts, lang=lang,
        ids=ids_str)

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
            user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
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
    _crm_conn.close()
    return render_template('admin/settings.html', s=s, qc_settings=qc_settings_list, lang=lang,
                           crm_materials=crm_materials)

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
            conn.execute("""INSERT INTO crm_materials (crm_name, mad_cert, aad_cert, vad_cert, sulfur_cert, cal_cert, notes)
                VALUES (?,?,?,?,?,?,?)""", (
                name,
                request.form.get('mad_cert') or None,
                request.form.get('aad_cert') or None,
                request.form.get('vad_cert') or None,
                request.form.get('sulfur_cert') or None,
                request.form.get('cal_cert') or None,
                request.form.get('notes', '').strip() or None,
            ))
            conn.commit()
            flash(f'CRM материал нэмэгдлээ: {name}', 'success')
        elif action == 'delete':
            mid = request.form.get('id')
            conn.execute("DELETE FROM crm_materials WHERE id=?", (mid,))
            conn.commit()
            flash('CRM материал устгагдлаа', 'success')
    finally:
        conn.close()
    return redirect(url_for('lab_settings') + '?tab=crm')

@app.route('/backup')
@admin_required
def backup_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'lab.db')
    from datetime import datetime as dt
    fname = f"lab_backup_{dt.now().strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(db_path, as_attachment=True, download_name=fname)

if __name__ == '__main__':
    init_db()
    from models import init_analysis_db
    init_analysis_db()

    # CRM migration
    _conn = get_db()
    for _col, _coltype in [
        ('crm_name', 'TEXT'),
        ('crm_mad', 'REAL'),
        ('crm_aad', 'REAL'),
        ('crm_vad', 'REAL'),
        ('crm_sulfur', 'REAL'),
        ('crm_cal', 'REAL'),
        ('sample_range', 'TEXT'),
    ]:
        try:
            _conn.execute(f'ALTER TABLE geo_samples ADD COLUMN {_col} {_coltype}')
        except Exception:
            pass
    _conn.execute("""INSERT OR IGNORE INTO sample_types (code, name_mn, name_en, icon, color, serial_from, serial_to, is_pit, is_active, sort_order)
        VALUES ('CRM','CRM дээж','CRM Sample','🔬','#7C3AED',9001,9999,0,1,10)""")
    _conn.execute("""CREATE TABLE IF NOT EXISTS crm_materials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        crm_name TEXT NOT NULL,
        mad_cert REAL,
        aad_cert REAL,
        vad_cert REAL,
        sulfur_cert REAL,
        cal_cert REAL,
        notes TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    _conn.commit()
    _conn.close()
    print('Систем эхэллээ!')
    print('Браузерт нэвтрэх: http://localhost:5000')
    print('ID: ADMIN  Нууц үг: admin123')
    app.run(debug=False, host='0.0.0.0', port=5000)
