"""Тооцоо нь байгаа ХЭРНЭЭ жин нь хоосон мөрүүдийг олно.

"Дэгдэмхий ардаа хариу нь байгаа хэрнээ масс нь алга болчиж" гэсэн
гомдлыг тоогоор нь баталгаажуулна: хэдэн мөрөнд, аль ажилд, ХЭЗЭЭ
болсныг гаргаж, асуудал үргэлжилж байгаа эсэхийг харуулна.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_lost.py
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_lost.py 2164-20260730
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_lost.py --since 2026-08-01

Тооцоо нь DB-д хадгалагдсан бол жин нь арилсан ч ХЭВЭЭР үлддэг (баталгаажсан
үр дүнг санамсаргүй устгахаас сэргийлсэн зориудын шийдэл). Тиймээс "хариу
байгаа, жин алга" гэдэг нь жин нь хожим арилсныг илтгэнэ.
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')

# (нэр, тооцооны багана, шаардагдах жингүүд)
GROUPS = [
    ('Дотоод чийг', 'mad',   ['dc_tare', 'dc_sample', 'dc_dried']),
    ('Үнслэг',      'aad',   ['ash_tare', 'ash_sample', 'ash_burned']),
    ('Дэгдэмхий',   'vad',   ['vol_tare', 'vol_sample', 'vol_burned']),
    ('G индекс',    'g_val', ['g_tare', 'g_coke', 'g_sieve1', 'g_sieve2']),
]


def label(d):
    return 'үндсэн' if d == 0 else 'зэрэгцээ' if d == 1 else f'давталт {d}'


def main():
    args = [a for a in sys.argv[1:]]
    since = None
    if '--since' in args:
        i = args.index('--since')
        since = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    lab_number = args[0] if args else None

    if not os.path.exists(DB):
        print(f'✗ DB олдсонгүй: {DB}')
        return 1
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    have = {r[1] for r in conn.execute('PRAGMA table_info(sample_entries)')}

    q = """SELECT sr.lab_number, sr.received_date, g.sample_type, u.name AS who, se.*
             FROM sample_entries se
             JOIN sample_receipt sr ON sr.id = se.receipt_id
             JOIN geo_samples g ON g.id = sr.geo_sample_id
             LEFT JOIN users u ON u.id = se.updated_by"""
    args_sql = []
    if lab_number:
        q += ' WHERE sr.lab_number = ?'
        args_sql.append(lab_number)
    q += ' ORDER BY sr.received_date, sr.lab_number, se.row_num, se.is_duplicate'
    rows = conn.execute(q, args_sql).fetchall()
    conn.close()

    if lab_number and not rows:
        print(f'✗ "{lab_number}" дугаартай ажил олдсонгүй.')
        return 1

    found, by_month, by_group = [], {}, {}
    for r in rows:
        for name, calc, raw in GROUPS:
            if calc not in have:
                continue
            cols = [c for c in raw if c in have]
            if r[calc] is None or not cols:
                continue
            gaps = [c for c in cols if r[c] is None]
            if not gaps or len(gaps) < len(cols):
                # Бүх жин байвал хэвийн. Зарим нь дутуу бол мөн адил
                # анхааруулна — гэхдээ БҮГД хоосон нь хамгийн тод шинж.
                if not gaps:
                    continue
            when = (r['updated_at'] or r['done_at'] or '')[:10]
            if since and when and when < since:
                continue
            found.append((r, name, calc, gaps, when))
            by_month[when[:7] or '—'] = by_month.get(when[:7] or '—', 0) + 1
            by_group[name] = by_group.get(name, 0) + 1

    if not found:
        print('✓ "Тооцоо байгаа ч жин нь хоосон" мөр олдсонгүй.')
        return 0

    print(f'⚠ Тооцоо нь байгаа ХЭРНЭЭ жин нь хоосон: {len(found)} тохиолдол\n')
    cur = None
    for r, name, calc, gaps, when in found:
        if r['lab_number'] != cur:
            cur = r['lab_number']
            print(f'══ {cur}  ({r["sample_type"]}, хүлээн авсан {r["received_date"]}) ══')
        val = r[calc]
        print(f'  мөр {r["row_num"]} «{r["sample_name"] or ""}» — {label(r["is_duplicate"])}'
              f'  [{r["row_status"]}]')
        print(f'      {name}: хадгалагдсан утга {val}   ХООСОН жин: {", ".join(gaps)}')
        if when:
            print(f'      сүүлд өөрчилсөн: {r["updated_at"] or r["done_at"]}'
                  f'{"  — " + r["who"] if r["who"] else ""}')
        print()

    print('── Сараар ──')
    for m in sorted(by_month):
        print(f'    {m}: {by_month[m]}')
    print('── Үзүүлэлтээр ──')
    for g, n in sorted(by_group.items(), key=lambda x: -x[1]):
        print(f'    {g:14} {n}')
    print()
    print('Тайлбар: тооцоо нь DB-д хадгалагдсан бол жин нь арилсан ч хэвээр')
    print('үлддэг (баталгаажсан үр дүнг хамгаалах зорилготой). Тиймээс энэ нь')
    print('жин нь ХОЖИМ арилсныг илтгэнэ. Огноог нь харвал асуудал одоо ч')
    print('үргэлжилж байгаа эсэхийг мэдэж болно.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
