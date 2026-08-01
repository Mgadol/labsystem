"""Хэмжилтийн хүснэгтээс хасах (сөрөг) утгыг олж жагсаана.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/find_negatives.py
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/find_negatives.py --fix

--fix өгвөл сөрөг утгыг хоосон болгож, тухайн мөрийн тооцоог дахин бодуулахаар
цэвэрлэнэ (устгахаас өмнө бүгдийг дэлгэцэд хэвлэнэ).
"""
import os
import sqlite3
import sys

# Жин, температур, илчлэг — аль нь ч сөрөг байж болохгүй талбарууд
NUM_FIELDS = [
    'mass_kg',
    'ff_sample', 'ff_dried',
    'mt_tare', 'mt_sample', 'mt_dried',
    'dc_tare', 'dc_sample', 'dc_dried',
    'ash_tare', 'ash_sample', 'ash_burned',
    'vol_tare', 'vol_sample', 'vol_burned',
    'g_tare', 'g_coke', 'g_sieve1', 'g_sieve2',
    'sulfur', 'cal_value', 'cal_temp', 'fsi',
]
CALC_FIELDS = ['mad', 'aad', 'vad', 'fc']

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')


def main():
    fix = '--fix' in sys.argv
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    have = {r['name'] for r in conn.execute('PRAGMA table_info(sample_entries)')}
    fields = [f for f in NUM_FIELDS + CALC_FIELDS if f in have]
    where = ' OR '.join(f'se.{f} < 0' for f in fields)

    rows = conn.execute(f"""
        SELECT se.id, se.receipt_id, se.row_num, se.is_duplicate, se.sample_name,
               se.row_status, sr.lab_number, {', '.join('se.' + f for f in fields)}
        FROM sample_entries se
        LEFT JOIN sample_receipt sr ON sr.id = se.receipt_id
        WHERE {where}
        ORDER BY se.receipt_id, se.row_num, se.is_duplicate""").fetchall()

    if not rows:
        print('✓ Сөрөг утга олдсонгүй — өгөгдөл цэвэр байна.')
        conn.close()
        return

    print(f'⚠ Сөрөг утгатай {len(rows)} мөр олдлоо:\n')
    for r in rows:
        bad = {f: r[f] for f in fields if r[f] is not None and r[f] < 0}
        dup = ('үндсэн' if r['is_duplicate'] == 0
               else 'зэрэгцээ' if r['is_duplicate'] == 1
               else f'давталт {r["is_duplicate"]}')
        print(f'  {r["lab_number"] or "?"}  мөр {r["row_num"]} ({dup})  '
              f'{r["sample_name"] or ""}  [{r["row_status"]}]')
        for f, v in bad.items():
            print(f'      {f} = {v}')

    if not fix:
        print('\nЗасахгүй — зөвхөн жагсаалт. Засахын тулд --fix нэмж ажиллуулна уу.')
        conn.close()
        return

    n = 0
    for r in rows:
        bad = [f for f in fields if r[f] is not None and r[f] < 0]
        sets = ', '.join(f'{f}=NULL' for f in bad)
        # Түүхий жин цэвэрлэгдвэл тухайн мөрийн тооцоог мөн хүчингүй болгоно
        if any(f in NUM_FIELDS for f in bad):
            sets += ', ' + ', '.join(f'{f}=NULL' for f in CALC_FIELDS if f in have)
        conn.execute(f'UPDATE sample_entries SET {sets} WHERE id=?', (r['id'],))
        n += 1
    conn.commit()
    conn.close()
    print(f'\n✓ {n} мөрийн сөрөг утга цэвэрлэгдэж, тооцоо хүчингүй болов.')
    print('  Хэмжилтийн хуудсыг нээж дахин хэмжилтийн жинг оруулна уу.')


if __name__ == '__main__':
    main()
