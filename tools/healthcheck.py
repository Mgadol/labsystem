"""Суулгацын эрүүл мэндийн шалгалт.

Шинэчлэлтийн ДАРАА ажиллуулж, код болон мэдээллийн сан бүрэн зөв
буусан эсэхийг батална. Хэрэглээ (серверт):

    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/healthcheck.py

Гаралт: бүх шалгалт OK бол 0, асуудалтай бол 1 буцаана (скриптэд ашиглаж болно).
"""
import os
import sqlite3
import sys
import warnings

warnings.filterwarnings('ignore')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

problems = []
notes = []


def ok(msg):
    print(f'  \033[32m✓\033[0m {msg}')


def bad(msg):
    print(f'  \033[31m✗\033[0m {msg}')
    problems.append(msg)


def warn(msg):
    print(f'  \033[33m!\033[0m {msg}')
    notes.append(msg)


print('═' * 64)
print('  ЛАБОРАТОРИЙН СИСТЕМ — ЭРҮҮЛ МЭНДИЙН ШАЛГАЛТ')
print('═' * 64)

# ── 1. Код ачаалагдаж байна уу ──
print('\n[1] Программ')
try:
    import app as A
except Exception as e:                                  # noqa: BLE001
    bad(f'Программ ачаалагдсангүй: {e}')
    print('\nҮүнээс цааш шалгах боломжгүй.')
    sys.exit(1)
ok(f'Хувилбар {A.VERSION}')

# Гит дэх байрлал — ямар коммит ажиллаж байгааг харуулна
try:
    import subprocess
    sha = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=ROOT,
                         capture_output=True, text=True, timeout=5).stdout.strip()
    br = subprocess.run(['git', 'branch', '--show-current'], cwd=ROOT,
                        capture_output=True, text=True, timeout=5).stdout.strip()
    if sha:
        ok(f'Код: {br or "(салбаргүй)"} @ {sha}')
        dirty = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT,
                               capture_output=True, text=True, timeout=5).stdout.strip()
        if dirty:
            warn(f'Сервер дээр хадгалагдаагүй өөрчлөлт байна '
                 f'({len(dirty.splitlines())} файл) — дараагийн git pull дарж устгаж болзошгүй')
except Exception:
    pass

# ── 2. Шилжилт ──
print('\n[2] Мэдээллийн сангийн шинэчлэлт')
if getattr(A, 'MIGRATIONS_COMPLETED', False):
    ok('Бүх шилжилт эцэс хүртэл ажиллав')
else:
    bad('Шилжилт ДУТУУ дуусав — зарим хүснэгт/багана дутуу байж болно')

mw = getattr(A, 'MIGRATION_WARNINGS', [])
if mw:
    bad(f'Шилжилтийн {len(mw)} алдаа:')
    for m in mw[:10]:
        print(f'      • {m}')
else:
    ok('Шилжилтийн алдаа алга')

# ── 3. Мэдээллийн сан ──
print('\n[3] Мэдээллийн сан')
DB = os.path.join(ROOT, 'instance', 'lab.db')
if not os.path.exists(DB):
    bad('instance/lab.db олдсонгүй')
else:
    size = os.path.getsize(DB) / 1048576
    ok(f'lab.db — {size:.1f} MB')
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    if conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok':
        ok('Бүрэн бүтэн байдал (integrity_check) — эвдрэлгүй')
    else:
        bad('Мэдээллийн сан ЭВДЭРСЭН байна')

    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    need = {'users', 'geo_samples', 'sample_receipt', 'sample_entries',
            'qc_settings', 'devices', 'calibrations', 'repairs', 'sample_types'}
    missing = need - tables
    if missing:
        bad(f'Дутуу хүснэгт: {", ".join(sorted(missing))}')
    else:
        ok(f'Шаардлагатай бүх хүснэгт байна ({len(tables)} нийт)')

    # Хэмжилтийн мөрийн гол баганууд
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(sample_entries)')}
    need_c = {'mad', 'aad', 'vad', 'fc', 'g_val', 'sulfur', 'cal_value', 'fsi',
              'row_status', 'done_at', 'approved_at', 'is_duplicate'}
    miss_c = need_c - cols
    if miss_c:
        bad(f'sample_entries дутуу багана: {", ".join(sorted(miss_c))}')
    else:
        ok(f'sample_entries — гол багана бүрэн ({len(cols)})')

    print('\n[4] Өгөгдлийн хэмжээ')
    for tbl, label in (('users', 'Хэрэглэгч'), ('geo_samples', 'Дээжийн бүртгэл'),
                       ('sample_receipt', 'Ажил'), ('sample_entries', 'Хэмжилтийн мөр'),
                       ('devices', 'Тоног төхөөрөмж')):
        try:
            n = conn.execute(f'SELECT COUNT(*) FROM {tbl}').fetchone()[0]
            print(f'      {label:20} {n:>8}')
        except sqlite3.Error:
            pass
    conn.close()

# ── 5. Тохиргоо ──
print('\n[5] Тохиргоо')
s = A.get_settings()
if s.get('lab_name') and s['lab_name'] != 'Лабораторийн нэр':
    ok(f'Лабораторийн нэр: {s["lab_name"]}')
else:
    warn('Лабораторийн нэр тохируулаагүй — Тохиргоо → Лабораторийн мэдээлэл')

lp = A.logo_path()
ok(f'Лого: {os.path.basename(lp)}' if lp else 'Лого олдсонгүй')

weak = getattr(A, 'WEAK_PASSWORD_USERS', [])
if weak:
    bad(f'{len(weak)} хэрэглэгч анхдагч admin123 нууц үгтэй — ЗААВАЛ солино уу:')
    for u in weak:
        print(f'      • {u}')
else:
    ok('Анхдагч admin123 нууц үгтэй хэрэглэгч алга')

if os.path.exists(os.path.join(ROOT, 'instance', 'ADMIN_PASSWORD.txt')):
    warn('instance/ADMIN_PASSWORD.txt үлдсэн байна — нууц үгээ сольсон бол устгана уу')

https = os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true'
(ok if https else warn)(
    'HTTPS_ENABLED=true — сешн күүки Secure тэмдэгтэй' if https else
    'HTTPS_ENABLED тавиагүй — интернэтэд гаргасан бол ЗААВАЛ тавина уу')

# ── 6. Нөөцлөлт ──
print('\n[6] Нөөцлөлт')
import glob
from datetime import datetime
bks = sorted(glob.glob(os.path.join(ROOT, 'instance', 'lab_backup_*.db')))
if not bks:
    warn('Нөөц хуулбар алга — систем ажиллаж эхэлсний дараа өдөр бүр үүснэ')
else:
    newest = max(bks, key=os.path.getmtime)
    age = (datetime.now() - datetime.fromtimestamp(os.path.getmtime(newest))).days
    msg = f'{len(bks)} хуулбар, хамгийн сүүлийнх {age} хоногийн өмнө'
    (ok if age <= 1 else warn)(msg)

# ── Дүгнэлт ──
print('\n' + '═' * 64)
if problems:
    print(f'  ✗ {len(problems)} АСУУДАЛ илэрлээ — засах шаардлагатай')
elif notes:
    print(f'  ✓ Ноцтой асуудалгүй, {len(notes)} анхаарах зүйл')
else:
    print('  ✓ БҮГД ХЭВИЙН')
print('═' * 64)
sys.exit(1 if problems else 0)
