"""Нэг дээжийн бүх мөрийг (үндсэн / зэрэгцээ / давталт) задлан харуулна.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_sample.py 2164-20260730 ROCK-6
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_sample.py 2164-20260730

Дээжийн нэр өгөхгүй бол тухайн ажлын бүх мөрийг харуулна.
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')

G_COLS = ['g_tig', 'g_tare', 'g_coke', 'g_sieve1', 'g_sieve2', 'g_val']
CALC = ['mad', 'aad', 'vad', 'fc']


def g_from_weights(r):
    """G = 10 + (30×(m3−m1) + 70×(m4−m1)) / (m2−m1)"""
    try:
        m1, m2, m3, m4 = (r['g_tare'], r['g_coke'], r['g_sieve1'], r['g_sieve2'])
        if None in (m1, m2, m3, m4) or (m2 - m1) <= 0:
            return None
        return 10 + (30 * (m3 - m1) + 70 * (m4 - m1)) / (m2 - m1)
    except (KeyError, TypeError):
        return None


def label(d):
    return 'үндсэн' if d == 0 else 'зэрэгцээ' if d == 1 else f'давталт {d}'


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    lab_number = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else None

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    rec = conn.execute('SELECT id, lab_number, geo_sample_id FROM sample_receipt '
                       'WHERE lab_number=?', (lab_number,)).fetchone()
    if not rec:
        print(f'✗ "{lab_number}" дугаартай ажил олдсонгүй.')
        conn.close()
        return

    # Дээжийн нэр ЗӨВХӨН үндсэн мөрөнд хадгалагддаг тул эхлээд мөрийн дугаарыг
    # олж, дараа нь тухайн мөрийн бүх хэмжилтийг (зэрэгцээ, давталт) авна.
    # Урьд нь нэрээр шүүж, зөвхөн үндсэн мөр олдоод "дундажлах юм алга" гэдэг байв.
    q = 'SELECT * FROM sample_entries WHERE receipt_id=?'
    args = [rec['id']]
    if name:
        nums = [r['row_num'] for r in conn.execute(
            'SELECT DISTINCT row_num FROM sample_entries '
            'WHERE receipt_id=? AND sample_name=?', (rec['id'], name))]
        if not nums:
            print(f'✗ {lab_number} дотор "{name}" нэртэй мөр олдсонгүй.')
            conn.close()
            return
        q += ' AND row_num IN (%s)' % ','.join('?' * len(nums))
        args += nums
    q += ' ORDER BY row_num, is_duplicate'
    rows = conn.execute(q, args).fetchall()

    if not rows:
        print(f'✗ {lab_number} дотор "{name}" мөр олдсонгүй.')
        conn.close()
        return

    have = rows[0].keys()
    cur = None
    for r in rows:
        if r['row_num'] != cur:
            cur = r['row_num']
            print(f'\n══ мөр {cur}  «{r["sample_name"]}» ══')
        gw = g_from_weights(r)
        gv = r['g_val'] if 'g_val' in have else None
        print(f'  ── {label(r["is_duplicate"])}  [{r["row_status"]}]')
        print('      G жин  : ' + '  '.join(
            f'{c}={r[c]}' for c in G_COLS if c in have and c != 'g_val'))
        print(f'      G жингээс бодогдох : '
              f'{"—" if gw is None else format(gw, ".1f")}')
        print(f'      G хадгалагдсан (g_val): {"—" if gv is None else gv}')
        print('      тооцоо : ' + '  '.join(
            f'{c}={r[c]}' for c in CALC if c in have))
        for f in ('done_at', 'approved_at', 'updated_at'):
            if f in have and r[f]:
                print(f'      {f}: {r[f]}')

    # Дүгнэлт: G-г дундажлах боломжтой эсэх
    print()
    cur = None
    for r in rows:
        if r['row_num'] == cur:
            continue
        cur = r['row_num']
        same = [x for x in rows if x['row_num'] == cur]
        gs = [(x['is_duplicate'],
               (x['g_val'] if 'g_val' in have and x['g_val'] is not None
                else g_from_weights(x)))
              for x in same]
        got = [(d, g) for d, g in gs if g is not None]
        txt = ', '.join(f'{label(d)}={g:.0f}' for d, g in got) or 'утга алга'
        if len(got) >= 2:
            vals = sorted(g for _, g in got)
            print(f'мөр {cur}: {txt}  →  дундаж {sum(vals[:2])/2:.0f}, '
                  f'зөрүү {abs(vals[1]-vals[0]):.0f}  ✓ дундажлагдана')
        else:
            print(f'мөр {cur}: {txt}  →  ✗ ЗӨВХӨН НЭГ УТГА — дундажлах юм алга')

    conn.close()


if __name__ == '__main__':
    main()
