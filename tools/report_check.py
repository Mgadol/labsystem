"""Тайлангийн график дээрх "Шинжилгээ дууссан дээж" жишиг шугам ба
үзүүлэлт бүрийн тоо хэрхэн бүрдэж байгааг задлан харуулна.

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

    # ── Жишиг шугам: шинжилгээ нь БҮРЭН ДУУССАН дээж (app.py-тай ижил) ──
    DONE_W = """se.is_duplicate=0 AND se.row_status IN ('done','approved')
                AND substr(se.done_at,1,10) BETWEEN ? AND ?"""
    base = conn.execute(f'SELECT COUNT(*) n FROM sample_entries se WHERE {DONE_W}',
                        (d0, d1)).fetchone()['n']
    print(f'Шинжилгээ дууссан дээж (жишиг шугам) : {base}')
    for r in conn.execute(
            f"""SELECT sr.lab_number, COUNT(*) n, COALESCE(g.quantity,1) qty
                FROM sample_entries se
                JOIN sample_receipt sr ON sr.id=se.receipt_id
                JOIN geo_samples g ON g.id=sr.geo_sample_id
                WHERE {DONE_W} GROUP BY sr.id ORDER BY sr.lab_serial""", (d0, d1)):
        part = '' if r['n'] == r['qty'] else f'   (ажлын {r["qty"]} дээжээс)'
        print(f'    {r["lab_number"]:22} {r["n"]:>4} дээж дууссан{part}')

    # ── Үзүүлэлт бүрийн тоо ──
    FIELDS = [('mt_dried', 'Нийт чийг'), ('mad', 'Дотоод чийг'), ('aad', 'Үнслэг'),
              ('vad', 'Дэгдэмхий'), ('sulfur', 'Хүхэр'), ('cal_value', 'Илчлэг'),
              ('COALESCE(se.g_val, se.g_coke)', 'G индекс'), ('fsi', 'ЧХЗ')]
    # Огноог мөрийнхөө ҮНДСЭН хэмжилтээс авна — зэрэгцээ, давталтын мөрөнд
    # "Дууслаа" товч байдаггүй тул тэдгээрийн done_at үргэлж хоосон
    # (app.py-гийн ANALYSIS_COUNT_SQL-тэй ижил дүрэм).
    print('\nҮзүүлэлт бүрийн тоо (үндсэн + зэрэгцээ + давталт):')
    JOIN_P = """JOIN sample_entries p ON p.receipt_id=se.receipt_id
                                     AND p.row_num=se.row_num
                                     AND p.is_duplicate=0
                WHERE p.row_status IN ('done','approved')
                  AND substr(p.done_at,1,10) BETWEEN ? AND ?"""
    for col, name in FIELDS:
        c = col if '(' in col else f'se.{col}'
        tot = conn.execute(f"""SELECT COUNT(*) n FROM sample_entries se {JOIN_P}
                               AND {c} IS NOT NULL""", (d0, d1)).fetchone()['n']
        if not tot:
            continue
        pri = conn.execute(f"""SELECT COUNT(*) n FROM sample_entries se {JOIN_P}
                               AND {c} IS NOT NULL AND se.is_duplicate=0""",
                           (d0, d1)).fetchone()['n']
        extra = f'  (үндсэн {pri} + давхар {tot - pri})' if tot != pri else ''
        flag = ''
        if pri > base:
            flag = f'  ⚠ жишгээс {pri - base}-аар их'
        print(f'    {name:16} {tot:>5}{extra}{flag}')

    # ── Багана яагаад улаан шугамаас доогуур байна вэ ──
    # Шугам = шинжилгээ нь дууссан дээжийн тоо. Багана = тухайн үзүүлэлтийн
    # хэмжилтийн тоо. Дууссан дээж бүр дээр БҮХ үзүүлэлтийг хэмждэггүй
    # (ж: баяжуулахын дээж, CRM) тул багана шугамаас доогуур байж БОЛНО.
    # Аль ажил дээр хэмжигдээгүйг нэрлэвэл зөв эсэхийг шууд шалгаж болно.
    if base:
        print(f'\nДууссан {base} дээжийн дотор үзүүлэлт бүр хэд дээр нь хэмжигдсэн:')
        for col, name in FIELDS:
            c = col if '(' in col else f'se.{col}'
            have = conn.execute(
                f'SELECT COUNT(*) n FROM sample_entries se '
                f'WHERE {DONE_W} AND {c} IS NOT NULL', (d0, d1)).fetchone()['n']
            miss = base - have
            print(f'    {name:16} {have:>5} / {base}'
                  + (f'   ⚠ {miss} дээж дээр хэмжигдээгүй' if miss else '   ✓ бүгд'))
            if miss:
                for r in conn.execute(
                        f"""SELECT sr.lab_number, g.sample_type, COUNT(*) n
                              FROM sample_entries se
                              JOIN sample_receipt sr ON sr.id=se.receipt_id
                              JOIN geo_samples g ON g.id=sr.geo_sample_id
                             WHERE {DONE_W} AND {c} IS NULL
                             GROUP BY sr.id ORDER BY n DESC LIMIT 8""", (d0, d1)):
                    print(f'          {r["lab_number"]:22} {r["sample_type"]:12} '
                          f'{r["n"]:>4} дээж')

    # ── ✓ дараагүй тул тоологдоогүй мөр ──
    pend = conn.execute(
        """SELECT COUNT(*) n FROM sample_entries se
           WHERE se.is_duplicate=0 AND se.row_status NOT IN ('done','approved')
             AND se.updated_at IS NOT NULL
             AND substr(se.updated_at,1,10) BETWEEN ? AND ?""", (d0, d1)).fetchone()['n']
    if pend:
        print(f'\n⚠ {pend} дээжид утга орсон ч мөр нь ✓ хийгдээгүй (дуусаагүй) тул')
        print('  энэ хугацааны тоонд ОРООГҮЙ. Дуусахаараа тухайн өдрийнхөө тоонд орно.')

    # ── done_at огноогүй мөр ──
    nodate = conn.execute(
        """SELECT COUNT(*) n FROM sample_entries se
           WHERE se.is_duplicate=0 AND se.row_status IN ('done','approved')
             AND se.done_at IS NULL""").fetchone()['n']
    if nodate:
        print(f'\n⚠ Нийт {nodate} дээж дууссан гэж тэмдэглэгдсэн ч дууссан огноогүй —')
        print('  эдгээр нь ямар ч хугацааны тоонд орохгүй.')
    conn.close()


if __name__ == '__main__':
    main()
