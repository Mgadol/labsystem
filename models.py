import sqlite3, os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'lab.db')

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        position TEXT,
        phone TEXT,
        email TEXT,
        photo TEXT,
        role TEXT DEFAULT 'staff',
        password_hash TEXT NOT NULL,
        joined_date TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS device_marks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manufacturer TEXT NOT NULL,
        model TEXT NOT NULL,
        category TEXT
    );
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        serial_number TEXT UNIQUE,
        mark_id INTEGER REFERENCES device_marks(id),
        location TEXT,
        purchase_date TEXT,
        warranty_expiry TEXT,
        calibration_interval INTEGER DEFAULT 90,
        photo TEXT,
        passport_pdf TEXT,
        status TEXT DEFAULT 'active',
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS staff_device_permissions (
        user_id INTEGER REFERENCES users(id),
        device_id INTEGER REFERENCES devices(id),
        PRIMARY KEY (user_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS calibrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES devices(id),
        performed_by INTEGER REFERENCES users(id),
        calibration_date TEXT NOT NULL,
        next_date TEXT,
        result TEXT DEFAULT 'passed',
        document TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS repairs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES devices(id),
        reported_by INTEGER REFERENCES users(id),
        reported_date TEXT NOT NULL,
        description TEXT NOT NULL,
        company TEXT,
        repair_date TEXT,
        cost REAL DEFAULT 0,
        photo TEXT,
        status TEXT DEFAULT 'open',
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES devices(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        start_time TEXT NOT NULL,
        end_time TEXT,
        duration_hours REAL,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    # Default admin
    cur = conn.execute("SELECT id FROM users WHERE employee_id='ADMIN'")
    if not cur.fetchone():
        pw = generate_password_hash('admin123')
        conn.execute("INSERT INTO users(employee_id,name,role,password_hash) VALUES('ADMIN','Систем Админ','admin',?)",(pw,))
        conn.execute("INSERT INTO device_marks(manufacturer,model,category) VALUES('Shimadzu','AUW220D','Жин хэмжих')")
        print("✓ DB initialized — ADMIN / admin123")
    conn.commit()
    conn.close()

def check_password(stored_hash, password):
    return check_password_hash(stored_hash, password)

def hash_password(password):
    return generate_password_hash(password)


def init_analysis_db():
    """Шинжилгээний модулийн хүснэгтүүд"""
    conn = get_db()
    conn.executescript('''

    -- Геологийн дээжний анхдагч бүртгэл
    CREATE TABLE IF NOT EXISTS geo_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sample_name TEXT NOT NULL,
        sample_type TEXT NOT NULL,  -- PIT/STOCKPILE/EXPORT/CONTROL/EQ_CONTROL/DP
        location TEXT,
        collected_date TEXT,
        quantity INTEGER DEFAULT 1,
        notes TEXT,
        registered_by INTEGER REFERENCES users(id),
        status TEXT DEFAULT 'pending',  -- pending/received/prepared/analysing/done
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Дээж бэлтгэгчийн хүлээн авалт
    CREATE TABLE IF NOT EXISTS sample_receipt (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        geo_sample_id INTEGER NOT NULL REFERENCES geo_samples(id),
        lab_number TEXT UNIQUE NOT NULL,  -- 1046-20260605
        lab_serial INTEGER NOT NULL,       -- 1046
        received_date TEXT NOT NULL,
        mass_kg REAL,                      -- Жин (кг)
        received_by INTEGER REFERENCES users(id),
        -- Нийт чийг (Mt) - Дээж бэлтгэгч хийнэ
        fm_sample_mass REAL,   -- Чөлөөт чийг: дээжний масс
        fm_dried_mass REAL,    -- Хатаасан масс
        fm_date TEXT,
        fm_operator INTEGER REFERENCES users(id),
        -- НЧ хэмжилт 1
        mt_tare1 REAL,         -- Хоосон бюкс
        mt_sample1 REAL,       -- Дээж
        mt_dried1 REAL,        -- Хатаасан масс
        mt_crucible1 TEXT,     -- Бюкс №
        mt_date TEXT,
        mt_shift TEXT,
        mt_operator INTEGER REFERENCES users(id),
        -- НЧ хэмжилт 2 (зэрэгцээ)
        mt_tare2 REAL,
        mt_sample2 REAL,
        mt_dried2 REAL,
        mt_crucible2 TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Шинжилгээний хэмжилтүүд (химич хийнэ)
    CREATE TABLE IF NOT EXISTS analysis_measurements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id INTEGER NOT NULL REFERENCES sample_receipt(id),
        is_duplicate INTEGER DEFAULT 0,  -- 0=үндсэн, 1=зэрэгцээ

        -- Дотоод чийг (Mad)
        im_tare1 REAL, im_sample1 REAL, im_dried1 REAL, im_crucible1 TEXT,
        im_tare2 REAL, im_sample2 REAL, im_dried2 REAL, im_crucible2 TEXT,
        im_date TEXT, im_shift TEXT, im_operator INTEGER REFERENCES users(id),
        im_device TEXT,

        -- Үнс (Aad)
        ash_tare1 REAL, ash_sample1 REAL, ash_burned1 REAL, ash_crucible1 TEXT,
        ash_tare2 REAL, ash_sample2 REAL, ash_burned2 REAL, ash_crucible2 TEXT,
        ash_date TEXT, ash_shift TEXT, ash_operator INTEGER REFERENCES users(id),
        ash_device TEXT,

        -- Дэгдэмхий бодис (Vad)
        vol_tare1 REAL, vol_sample1 REAL, vol_burned1 REAL, vol_crucible1 TEXT,
        vol_tare2 REAL, vol_sample2 REAL, vol_burned2 REAL, vol_crucible2 TEXT,
        vol_date TEXT, vol_shift TEXT, vol_operator INTEGER REFERENCES users(id),
        vol_device TEXT,

        -- Нийт хүхэр (Stad)
        sulfur1 REAL, sulfur2 REAL,
        sulfur_date TEXT, sulfur_shift TEXT, sulfur_operator INTEGER REFERENCES users(id),

        -- Илчлэг (Qb,ad)
        cal_value1 REAL, cal_room_temp1 REAL,
        cal_value2 REAL, cal_room_temp2 REAL,
        cal_date TEXT, cal_shift TEXT, cal_operator INTEGER REFERENCES users(id),

        -- G индекс
        g_tare REAL, g_coke REAL, g_sieve1 REAL, g_sieve2 REAL,
        g_tare2 REAL, g_coke2 REAL, g_sieve1b REAL, g_sieve2b REAL,
        g_crucible TEXT, g_date TEXT, g_shift TEXT,
        g_operator INTEGER REFERENCES users(id), g_device TEXT,

        -- FSI/CSN
        fsi_value1 REAL, fsi_value2 REAL,
        fsi_date TEXT, fsi_shift TEXT, fsi_operator INTEGER REFERENCES users(id),

        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Тооцоолсон үр дүн (автомат)
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id INTEGER NOT NULL REFERENCES sample_receipt(id),
        -- Чийг
        Mt REAL,   -- Нийт чийг
        Mad REAL,  -- Дотоод чийг (ad)
        -- Үнс
        Aad REAL, Adb REAL,
        -- Дэгдэмхий
        Vad REAL, Vdb REAL, Vdaf REAL,
        -- Бэхэжсэн нүүрстөрөгч
        FCad REAL,
        -- Хүхэр
        Stad REAL, Std REAL,
        -- Илчлэг
        Qb_ad_jg REAL, Qb_ad_kcal REAL,
        Qgr_ad REAL, Qgr_ar REAL,
        Qnet_ar REAL,
        -- Нэмэлт
        Had REAL, Hdaf REAL, Vdaf_calc REAL,
        -- G, FSI
        G_index REAL, FSI REAL, Y_index REAL,
        -- QC статус
        qc_status TEXT DEFAULT 'pending',  -- pending/passed/warning/failed
        qc_notes TEXT,
        -- Баталгаажуулалт
        approved_by INTEGER REFERENCES users(id),
        approved_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- QC тохиргоо (админ тохируулна)
    CREATE TABLE IF NOT EXISTS qc_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parameter TEXT NOT NULL UNIQUE,   -- Mad, Aad, Vad, Stad, Qb_ad, G, FSI
        tolerance REAL NOT NULL,   -- Зөвшөөрөгдөх зөрүү
        standard TEXT,             -- GB/T 212 гэх мэт
        updated_by INTEGER REFERENCES users(id),
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Тайлангийн бүртгэл
    CREATE TABLE IF NOT EXISTS analysis_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id INTEGER NOT NULL REFERENCES sample_receipt(id),
        report_number TEXT UNIQUE,
        published_date TEXT,
        approved_by INTEGER REFERENCES users(id),
        pdf_path TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Анхны QC тохиргоо
    INSERT OR IGNORE INTO qc_settings(parameter, tolerance, standard) VALUES
        ('Mad', 0.20, 'MNS GB/T 212-2015'),
        ('Aad', 0.30, 'MNS GB/T 212-2015'),
        ('Vad', 0.30, 'MNS GB/T 212-2015'),
        ('Stad', 0.03, 'MNS GB/T 214-2024'),
        ('Qb_ad', 120, 'MNS GB/T 213-2024'),
        ('G_index', 3.0, 'GB/T 5447:2014'),
        ('FSI', 0.5, 'GB/T 5448-2014');

    ''')
    conn.commit()
    conn.close()
    print("Analysis DB initialized")
