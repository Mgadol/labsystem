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

    # ── Бэлтгэсэн дээж ──
    prep = conn.execute(
        """SELECT sr.id rid, sr.lab_number, COALESCE(g.quantity,1) qty,
                  substr(sr.prep_done_at,1,10) d
           FROM sample_receipt sr JOIN geo_samples g ON g.id=sr.geo_sample_id
           WHERE sr.prep_done_at IS NOT NULL
             AND substr(sr.prep_done_at,1,10) BETWEEN ? AND ?
           ORDER BY sr.lab_serial""", (d0, d1)).fetchall()
    n_prep = sum(r['qty'] for r in prep)
    print(f'Бэлтгэсэн дээж : {n_prep}   ({len(prep)} ажил)')
    for r in prep:
        print(f'    {r["lab_number"]:22} {r["qty"]:>4} дээж   бэлтгэсэн {r["d"]}')

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

    # ── Хугацаанаас гадуур ороогүй/орсон ──
    out = conn.execute(
        """SELECT COUNT(DISTINCT se.receipt_id || '-' || se.row_num) n
           FROM sample_entries se JOIN sample_receipt sr ON sr.id=se.receipt_id
           WHERE se.mt_dried IS NOT NULL
             AND substr(se.done_at,1,10) BETWEEN ? AND ?
             AND (sr.prep_done_at IS NULL
                  OR substr(sr.prep_done_at,1,10) NOT BETWEEN ? AND ?)""",
        (d0, d1, d0, d1)).fetchone()['n']
    if out:
        print(f'\n⚠ {out} дээж энэ хугацаанд ШИНЖЛЭГДСЭН ч бэлтгэл нь өөр '
              f'хугацаанд хийгдсэн\n  (эсвэл бэлтгэлийн огноо бүртгэгдээгүй) '
              f'— тиймээс хоёр тоо зөрнө.')

    no_prep = conn.execute(
        """SELECT COUNT(*) n FROM sample_receipt WHERE prep_done_at IS NULL""").fetchone()['n']
    if no_prep:
        print(f'\n⚠ Нийт {no_prep} ажилд бэлтгэл дууссан огноо (prep_done_at) '
              f'огт бүртгэгдээгүй байна.\n  Эдгээр нь "Дээж бэлтгэл" тоонд '
              f'хэзээ ч орохгүй.')
    conn.close()


if __name__ == '__main__':
    main()
