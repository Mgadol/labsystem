"""Ажилтны «шинжилсэн дээж» тоо яагаад бага гарч байгааг задлан харуулна.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/staff_stats.py Оюунбилэг
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/staff_stats.py           # бүх ажилтан

Одоогийн статистик зөвхөн «Дууслаа» (✓) товч дарсан мөрийг тоолдог
(done_by). Хэмжилт оруулсан ч ✓ дараагүй бол тоологдохгүй — энэ скрипт
хоёрын зөрүүг харуулна.
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')

# Хэмжилтийн аль нэг утга орсон эсэхийг илтгэх багана
VALUE_COLS = ['ff_sample', 'ff_dried', 'mt_tare', 'mt_sample', 'mt_dried',
              'dc_tare', 'dc_sample', 'dc_dried', 'ash_tare', 'ash_sample',
              'ash_burned', 'vol_tare', 'vol_sample', 'vol_burned',
              'g_tare', 'g_coke', 'g_sieve1', 'g_sieve2',
              'sulfur', 'cal_value', 'fsi', 'mad', 'aad', 'vad', 'g_val']


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else None
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    have = {r['name'] for r in conn.execute('PRAGMA table_info(sample_entries)')}
    cols = [c for c in VALUE_COLS if c in have]
    any_val = ' OR '.join(f'{c} IS NOT NULL' for c in cols)
    has_upd = 'updated_by' in have

    q = 'SELECT id, name, role FROM users WHERE is_active=1'
    args = []
    if name:
        q += ' AND name LIKE ?'
        args.append(f'%{name}%')
    users = conn.execute(q + ' ORDER BY name', args).fetchall()
    if not users:
        print(f'✗ "{name}" нэртэй идэвхтэй ажилтан олдсонгүй.')
        conn.close()
        return

    for u in users:
        uid = u['id']
        print(f'\n══ {u["name"]}  ({u["role"]}) ══')

        # 1) Одоогийн статистикийн тоо — ✓ дарсан мөр (давталт орсон)
        cur = conn.execute("""SELECT COUNT(*) c FROM sample_entries
                              WHERE done_by=? AND row_status IN ('done','approved')""",
                           (uid,)).fetchone()['c']
        print(f'  Одоогийн "шинжилсэн дээж"            : {cur}')

        # 2) Мөн адил, гэхдээ зэрэгцээ/давталтыг оруулахгүй
        main_only = conn.execute("""SELECT COUNT(*) c FROM sample_entries
                                    WHERE done_by=? AND is_duplicate=0
                                      AND row_status IN ('done','approved')""",
                                 (uid,)).fetchone()['c']
        print(f'    үүнээс үндсэн мөр (зэрэгцээгүй)   : {main_only}')

        if not has_upd:
            print('  (updated_by багана байхгүй — хуучин DB)')
            continue

        # 3) Утга оруулсан дээж — ✓ дарсан эсэхээс үл хамааран
        touched = conn.execute(f"""
            SELECT COUNT(*) c FROM sample_entries
            WHERE updated_by=? AND is_duplicate=0 AND ({any_val})""",
            (uid,)).fetchone()['c']
        print(f'  Утга оруулсан дээж (updated_by)      : {touched}')

        touched_all = conn.execute(f"""
            SELECT COUNT(*) c FROM sample_entries
            WHERE updated_by=? AND ({any_val})""", (uid,)).fetchone()['c']
        print(f'    зэрэгцээ/давталт оруулаад          : {touched_all}')

        # 4) Утга оруулсан ч ✓ дараагүй
        gap = conn.execute(f"""
            SELECT COUNT(*) c FROM sample_entries
            WHERE updated_by=? AND is_duplicate=0 AND ({any_val})
              AND (done_by IS NULL OR done_by<>?)""", (uid, uid)).fetchone()['c']
        print(f'  → Оруулсан ч ✓ дараагүй / өөр хүн дарсан: {gap}')

        # 5) Хэдэн ажил (лот) дээр ажилласан
        lots = conn.execute(f"""
            SELECT COUNT(DISTINCT receipt_id) c FROM sample_entries
            WHERE updated_by=? AND ({any_val})""", (uid,)).fetchone()['c']
        print(f'  Ажилласан ажлын тоо (лот)            : {lots}')

    # ── ✓ товч хэн дардаг вэ — бүх ажилтнаар ──
    print('\n══ «Дууслаа» ✓ дарсан тоо (бүх ажилтан) ══')
    for r in conn.execute("""
            SELECT u.name, COUNT(*) c FROM sample_entries se
            JOIN users u ON u.id=se.done_by
            WHERE se.row_status IN ('done','approved')
            GROUP BY u.id ORDER BY c DESC"""):
        print(f'  {r["name"]:24} {r["c"]}')

    orphan = conn.execute("""SELECT COUNT(*) c FROM sample_entries
                             WHERE row_status IN ('done','approved')
                               AND done_by IS NULL""").fetchone()['c']
    if orphan:
        print(f'  (эзэнгүй — done_by хоосон): {orphan}')

    conn.close()


if __name__ == '__main__':
    main()
