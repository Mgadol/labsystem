"""Тайлангийн график дээрх "Дээж бэлтгэл" ба шинжилгээний тоо яагаад
зөрж байгааг задлан харуулна.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/report_check.py 2026-08-03 2026-08-09
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/report_check.py 2026-08          # сар
"""
import os
import sqlite3
import sys
from calendar import monthrange

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    a = sys.argv[1]
    if len(sys.argv) > 2:
        d0, d1 = a, sys.argv[2]
    elif len(a) == 7:                      # '2026-08'
        y, m = (int(x) for x in a.split('-'))
        d0, d1 = f'{a}-01', f'{a}-{monthrange(y, m)[1]:02d}'
    else:
        d0 = d1 = a

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    print(f'══ {d0} … {d1} ══\n')

    # app.py-тай ижил логик: prep_done_at байхгүй бол огноог нөхнө
    PREP_DATE = "COALESCE(sr.prep_done_at, sr.prep_started_at, sr.received_date)"
    PREP_COND = """(sr.prep_done_at IS NOT NULL
                    OR sr.prep_status IN ('ready','done')
                    OR EXISTS (SELECT 1 FROM sample_entries se2
                               WHERE se2.receipt_id = sr.id))"""

    # ── Бэлтгэсэн дээж — хуучин (зөвхөн prep_done_at) ба шинэ (нөхөлттэй) ──
    old = conn.execute(
        """SELECT COALESCE(SUM(COALESCE(g.quantity,1)),0) n
           FROM sample_receipt sr JOIN geo_samples g ON g.id=sr.geo_sample_id
           WHERE sr.prep_done_at IS NOT NULL
             AND substr(sr.prep_done_at,1,10) BETWEEN ? AND ?""",
        (d0, d1)).fetchone()['n']
    prep = conn.execute(
        f"""SELECT sr.id rid, sr.lab_number, COALESCE(g.quantity,1) qty,
                   substr({PREP_DATE},1,10) d,
                   sr.prep_done_at IS NULL nofin
            FROM sample_receipt sr JOIN geo_samples g ON g.id=sr.geo_sample_id
            WHERE {PREP_COND}
              AND substr({PREP_DATE},1,10) BETWEEN ? AND ?
            ORDER BY sr.lab_serial""", (d0, d1)).fetchall()
    n_prep = sum(r['qty'] for r in prep)
    print(f'Бэлтгэсэн дээж : {n_prep}   ({len(prep)} ажил)')
    print(f'  үүнээс "дууслаа" товч дарагдсан : {old}')
    if n_prep != old:
        print(f'  огноо нөхөж тооцсон             : {n_prep - old}   ← өмнө нь алга байсан')
    for r in prep:
        mark = '  ⚠ огноо нөхсөн' if r['nofin'] else ''
        print(f'    {r["lab_number"]:22} {r["qty"]:>4} дээж   бэлтгэсэн {r["d"]}{mark}')

    # ── Нийт чийг хэмжсэн дээж — done_at-аар (график ингэж тоолдог) ──
    by_done = conn.execute(
        """SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num) n
           FROM sample_entries se
           WHERE se.mt_dried IS NOT NULL
             AND substr(se.done_at,1,10) BETWEEN ? AND ?""", (d0, d1)).fetchone()['n']
    # ── ✓ дараагүй ч утга орсныг оруулаад ──
    by_any = conn.execute(
        """SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num) n
           FROM sample_entries se
           WHERE se.mt_dried IS NOT NULL
             AND substr(COALESCE(se.done_at, se.updated_at),1,10) BETWEEN ? AND ?""",
        (d0, d1)).fetchone()['n']
    print(f'\nНийт чийг (done_at-аар, график)      : {by_done}')
    print(f'Нийт чийг (✓ дараагүйг оруулаад)     : {by_any}')

    # ── Бэлтгэсэн ажлуудын дээж дээр Mt хийгдсэн эсэх ──
    if prep:
        rids = [r['rid'] for r in prep]
        ph = ','.join('?' * len(rids))
        mt_in_prep = conn.execute(
            f"""SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num) n
                FROM sample_entries se
                WHERE se.mt_dried IS NOT NULL AND se.receipt_id IN ({ph})""",
            rids).fetchone()['n']
        print(f'\nЭнэ хугацаанд бэлтгэсэн ажлуудын дотор Mt хэмжсэн дээж: '
              f'{mt_in_prep} / {n_prep}')
        if mt_in_prep < n_prep:
            print(f'  → {n_prep - mt_in_prep} дээж дээр Mt хэмжигдээгүй')
        for r in prep:
            got = conn.execute(
                """SELECT COUNT(DISTINCT row_num) n FROM sample_entries
                   WHERE receipt_id=? AND mt_dried IS NOT NULL""",
                (r['rid'],)).fetchone()['n']
            if got != r['qty']:
                print(f'    {r["lab_number"]:22} {got}/{r["qty"]} дээж дээр Mt')

    # ── Нийт чийгийн мөрүүдийг is_duplicate-аар задална ──
    print('\nНийт чийгийн хэмжилт (мөрөөр, done_at-аар):')
    tot = 0
    for r in conn.execute(
            """SELECT se.is_duplicate d, COUNT(*) n FROM sample_entries se
               WHERE se.mt_dried IS NOT NULL
                 AND substr(se.done_at,1,10) BETWEEN ? AND ?
               GROUP BY se.is_duplicate ORDER BY se.is_duplicate""", (d0, d1)):
        lbl = 'үндсэн' if r['d'] == 0 else ('зэрэгцээ' if r['d'] == 1
                                            else f'давталт {r["d"]}')
        print(f'    {lbl:12} {r["n"]}')
        tot += r['n']
    print(f'    {"НИЙТ":12} {tot}')
    if tot > by_done:
        print(f'  → График {tot} гэж харуулна ({by_done} дээж дээр хийгдсэн). '
              f'Нийт чийгийг давтаж хэмжсэн бол ийм зөрүү гарна.')

    # ── Энэ хугацаанд шинжлэгдсэн ч бэлтгэл нь тохирохгүй дээжийг ЯЛГАНА ──
    print('\nЭнэ хугацаанд Mt хэмжигдсэн дээжийн бэлтгэл хаана тоологдсон бэ:')
    cats = conn.execute(
        f"""SELECT CASE
                     WHEN substr({PREP_DATE},1,10) BETWEEN ? AND ? THEN 'in'
                     WHEN {PREP_DATE} IS NOT NULL                  THEN 'other'
                     ELSE 'none' END k,
                   COUNT(DISTINCT se.receipt_id || '-' || se.row_num) n
            FROM sample_entries se JOIN sample_receipt sr ON sr.id=se.receipt_id
            WHERE se.mt_dried IS NOT NULL
              AND substr(se.done_at,1,10) BETWEEN ? AND ?
            GROUP BY k""", (d0, d1, d0, d1)).fetchall()
    lbl = {'in': 'мөн энэ хугацаанд бэлтгэгдсэн',
           'other': 'ӨӨР хугацаанд бэлтгэгдсэн  (огнооны зөрүү)',
           'none': 'бэлтгэлийн огноо огт алга    (нөхөх боломжгүй)'}
    for r in cats:
        print(f'    {lbl[r["k"]]:44} {r["n"]:>5}')

    # ── Огноо нөхөх боломжтой байсан ажлууд ──
    fixed = conn.execute(
        f"""SELECT sr.lab_number, substr({PREP_DATE},1,10) d, sr.prep_status,
                   COALESCE(g.quantity,1) qty
            FROM sample_receipt sr JOIN geo_samples g ON g.id=sr.geo_sample_id
            WHERE sr.prep_done_at IS NULL AND {PREP_COND}
            ORDER BY sr.lab_serial""").fetchall()
    if fixed:
        print(f'\n⚠ "Дээж бэлтгэж дууслаа" товч дарагдаагүй {len(fixed)} ажил '
              f'({sum(r["qty"] for r in fixed)} дээж):')
        for r in fixed:
            print(f'    {r["lab_number"]:22} {r["qty"]:>4} дээж   '
                  f'нөхсөн огноо {r["d"]}   ({r["prep_status"]})')
        print('  Эдгээр нь өмнө нь графикт ОГТ тоологдохгүй байсан.')
        print('  Цаашид бэлтгэгч "Дээж бэлтгэж дууслаа" товчийг заавал дарах ёстой —')
        print('  тэгвэл бэлтгэлийн жинхэнэ огноо, хийсэн хүн, тоног төхөөрөмж бүртгэгдэнэ.')
    conn.close()


if __name__ == '__main__':
    main()
