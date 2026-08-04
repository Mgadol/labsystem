"""Ажлын төлөв (geo_samples.status) ба мөрүүдийн байдлыг тулгаж харуулна.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/job_status.py 6000     # 6000-6999 муж
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/job_status.py 6169-20260802
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/job_status.py          # бүх дуусаагүй

Ажил "дууссан" болохын тулд ҮНДСЭН мөр бүр (is_duplicate=0) approved байх
ёстой. Хэрэв нэг ч мөр дутуу/баталгаажаагүй бол geo_samples.status нь
'done' болохгүй тул Шинжилгээ хуудсанд үлдэнэ.
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    q = """SELECT sr.id rid, sr.lab_number, sr.lab_serial, sr.prep_status,
                  g.id gid, g.status, g.quantity, g.sample_name
           FROM sample_receipt sr JOIN geo_samples g ON g.id=sr.geo_sample_id"""
    args = []
    if arg and arg.isdigit():
        lo = int(arg) // 1000 * 1000
        q += ' WHERE sr.lab_serial BETWEEN ? AND ?'
        args = [lo, lo + 999]
        title = f'{lo}-{lo + 999} муж'
    elif arg:
        q += ' WHERE sr.lab_number=?'
        args = [arg]
        title = arg
    else:
        q += " WHERE g.status != 'done'"
        title = 'дуусаагүй бүх ажил'
    q += ' ORDER BY sr.lab_serial DESC LIMIT 100'

    rows = conn.execute(q, args).fetchall()
    if not rows:
        print(f'✗ "{title}"-д тохирох ажил олдсонгүй.')
        conn.close()
        return

    print(f'══ {title} — {len(rows)} ажил ══\n')
    bad = 0
    for r in rows:
        st = {x[0]: x[1] for x in conn.execute(
            """SELECT COALESCE(row_status,'empty'), COUNT(*) FROM sample_entries
               WHERE receipt_id=? AND is_duplicate=0
               GROUP BY COALESCE(row_status,'empty')""", (r['rid'],))}
        n_rows = sum(st.values())
        qty = r['quantity'] or 1
        appr = st.get('approved', 0)
        # Систем "дууссан" гэж үзэх нөхцөл: БАЙГАА үндсэн мөр бүр approved
        would_be_done = n_rows > 0 and n_rows == appr
        shown = 'АРХИВТ' if r['status'] == 'done' else 'Шинжилгээ хуудсанд'
        flag = ''
        if r['status'] != 'done' and would_be_done:
            flag = '  ← бүх мөр баталгаажсан ч төлөв шинэчлэгдээгүй'
            if qty > n_rows:
                flag += f' ({qty - n_rows} дээж огт хөндөгдөөгүй)'
            bad += 1
        elif r['status'] != 'done' and qty > n_rows and appr == n_rows:
            flag = f'  ← {qty - n_rows} дээж огт хөндөгдөөгүй (мөр үүсээгүй)'
        elif r['status'] != 'done':
            miss = ', '.join(f'{k}={v}' for k, v in sorted(st.items()) if k != 'approved')
            flag = f'  ← баталгаажаагүй мөр: {miss or "алга"}'
        print(f'{r["lab_number"]:22} төлөв={r["status"]:10} {shown}')
        print(f'    дээж {qty}, мөр {n_rows}, баталгаажсан {appr}'
              f'   [{", ".join(f"{k}:{v}" for k, v in sorted(st.items())) or "мөргүй"}]{flag}')

    if bad:
        print(f'\n⚠ {bad} ажлын бүх мөр баталгаажсан атлаа төлөв нь "done" болоогүй.')
        print('  Үр дүнгийн хуудсаас нэг мөрийг дахин баталгаажуулбал төлөв шинэчлэгдэнэ.')
    else:
        print('\n✓ Төлөв ба мөрүүдийн байдал зөрчилгүй.')
    conn.close()


if __name__ == '__main__':
    main()
