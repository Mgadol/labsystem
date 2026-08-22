"""«Шинжилсэн дээж» ба «дуусгасан» хоёрын ЗӨРҮҮГ задлан харуулна.

Ажилтны хуудсанд жишээ нь «Шинжилсэн дээж 28 / дуусгасан 24» гэж гарвал
энэ скрипт тэр 4 дээж яг аль нь болох, яагаад дуусаагүй байгааг жагсаана.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/staff_gap.py Соёлмаа
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/staff_gap.py        # бүх ажилтан
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')

OPS = [
    ('op_mt', 'Нийт чийг', ['ff_sample', 'ff_dried', 'mt_bux', 'mt_tare',
                            'mt_sample', 'mt_dried']),
    ('op_mad', 'Дотоод чийг', ['dc_bux', 'dc_tare', 'dc_sample', 'dc_dried']),
    ('op_aad', 'Үнслэг', ['ash_tav', 'ash_tare', 'ash_sample', 'ash_burned']),
    ('op_vad', 'Дэгдэмхий', ['vol_tig', 'vol_tare', 'vol_sample', 'vol_burned']),
    ('op_g', 'G индекс', ['g_tig', 'g_tare', 'g_coke', 'g_sieve1', 'g_sieve2']),
    ('op_st', 'Нийт хүхэр', ['sulfur']),
    ('op_q', 'Илчлэг', ['cal_value', 'cal_temp']),
    ('op_fsi', 'Чөлөөт хөөлт', ['fsi']),
]

STATUS_MN = {'empty': 'хоосон — ✓ дараагүй',
             'done': '✓ дарсан — БАТАЛГААЖААГҮЙ', 'approved': 'баталгаажсан'}


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else None
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    have = {r[1] for r in conn.execute('PRAGMA table_info(sample_entries)')}
    ops = [(o, l, [f for f in fs if f in have]) for o, l, fs in OPS if o in have]
    ops = [(o, l, fs) for o, l, fs in ops if fs]
    if not ops:
        print('op_* багана байхгүй — программаа шинэчилнэ үү.')
        return 1
    # Гүйцэтгэгчийн тэмдэгтэй БӨГӨӨД утга нь үлдсэн мөр (программтай ижил дүрэм)
    any_op = ' OR '.join(
        f'(se.{o}=? AND (' + ' OR '.join(f'se.{f} IS NOT NULL' for f in fs) + '))'
        for o, _l, fs in ops)
    # Зөвхөн тэмдэг нь үлдсэн, утга нь АРИЛСАН мөр — "сүүдэр" мөр
    ghost_op = ' OR '.join(
        f'(se.{o}=? AND NOT (' + ' OR '.join(f'se.{f} IS NOT NULL' for f in fs) + '))'
        for o, _l, fs in ops)

    q = 'SELECT id, name, role FROM users WHERE is_active=1'
    args = []
    if name:
        q += ' AND name LIKE ?'
        args.append(f'%{name}%')
    users = conn.execute(q + ' ORDER BY name', args).fetchall()
    if not users:
        print(f'"{name}" нэртэй идэвхтэй ажилтан олдсонгүй.')
        return 1

    for u in users:
        uid = (u['id'],)
        n_ops = tuple(u['id'] for _ in ops)
        analysed = conn.execute(
            f"""SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num)
                FROM sample_entries se WHERE {any_op}""", n_ops).fetchone()[0]
        done = conn.execute(
            f"""SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num)
                FROM sample_entries se
                JOIN sample_entries p ON p.receipt_id=se.receipt_id
                                     AND p.row_num=se.row_num AND p.is_duplicate=0
                WHERE ({any_op}) AND p.row_status='approved'""",
            n_ops).fetchone()[0]
        ghosts = conn.execute(
            f"""SELECT DISTINCT se.receipt_id, se.row_num, sr.lab_number,
                       g.sample_name, g.sample_type
                FROM sample_entries se
                LEFT JOIN sample_receipt sr ON sr.id=se.receipt_id
                LEFT JOIN geo_samples g ON g.id=sr.geo_sample_id
                WHERE ({ghost_op})
                  AND se.receipt_id || '-' || se.row_num NOT IN (
                      SELECT s2.receipt_id || '-' || s2.row_num
                      FROM sample_entries s2 WHERE {any_op.replace('se.', 's2.')})
                ORDER BY sr.lab_number, se.row_num""", n_ops + n_ops).fetchall()
        if not analysed and not ghosts:
            continue
        print(f'\n═══ {u["name"]} ({u["role"]}) ═══')
        print(f'  Шинжилсэн дээж: {analysed}   дуусгасан: {done}   ЗӨРҮҮ: {analysed - done}')
        if ghosts:
            print(f'\n  ⚠ Утга нь арилсан «сүүдэр» мөр: {len(ghosts)} '
                  f'(тоологдохгүй — утга шивээд буцаагаад арилгасан байна)')
            for r in ghosts:
                print(f'    {r["lab_number"] or "?":18} мөр {r["row_num"]:>3}  '
                      f'{r["sample_type"] or "—":10} {(r["sample_name"] or "")[:30]}')
            print('    Хэрэв энэ утга САНАМСАРГҮЙ арилсан бол:')
            print('      tools/check_audit.py --cleared   ← хэзээ, хэн арилгасныг харна')
        if analysed == done:
            print('  ✓ Зөрүүгүй — бүх дээж нь дууссан.')
            continue

        rows = conn.execute(
            f"""SELECT DISTINCT se.receipt_id, se.row_num,
                       p.row_status, p.done_at,
                       sr.lab_number, g.sample_name, g.sample_type, g.status AS gstatus
                FROM sample_entries se
                JOIN sample_entries p ON p.receipt_id=se.receipt_id
                                     AND p.row_num=se.row_num AND p.is_duplicate=0
                LEFT JOIN sample_receipt sr ON sr.id=se.receipt_id
                LEFT JOIN geo_samples g ON g.id=sr.geo_sample_id
                WHERE ({any_op}) AND (p.row_status IS NULL
                                      OR p.row_status<>'approved')
                ORDER BY sr.lab_number, se.row_num""", n_ops).fetchall()
        print(f'\n  Дуусаагүй тул тоологдоогүй {len(rows)} дээж:')
        print(f'    {"Ажлын дугаар":18} {"мөр":>4}  {"төрөл":10} {"мөрийн байдал":22} дээжийн нэр')
        for r in rows:
            st = STATUS_MN.get(r['row_status'], r['row_status'] or 'мөр алга')
            print(f'    {r["lab_number"] or "?":18} {r["row_num"]:>4}  '
                  f'{r["sample_type"] or "—":10} {st:22} {(r["sample_name"] or "")[:30]}')
        print('\n  Тайлбар: эдгээр дээж дээр шинжилгээ хийгдсэн ч хараахан')
        print('  БАТАЛГААЖААГҮЙ байна (ахлах химич баталгаажуулаагүй, эсвэл')
        print('  ✓ товч дарагдаагүй). Баталгаажмагц «дуусгасан» тоо нь')
        print('  «Шинжилсэн дээж»-тэй тэнцэнэ.')
    conn.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
