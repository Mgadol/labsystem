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

# Шинжилгээний бүлэг тус бүрийн түүхий жин — аль нүд хоосон байгааг харуулна
GROUPS = [
    ('Чөлөөт чийг', ['ff_sample', 'ff_dried']),
    ('Нийт чийг',   ['mt_bux', 'mt_tare', 'mt_sample', 'mt_dried']),
    ('Дотоод чийг', ['dc_bux', 'dc_tare', 'dc_sample', 'dc_dried']),
    ('Үнслэг',      ['ash_tav', 'ash_tare', 'ash_sample', 'ash_burned']),
    ('Дэгдэмхий',   ['vol_tig', 'vol_tare', 'vol_sample', 'vol_burned']),
    ('Бусад',       ['sulfur', 'cal_value', 'cal_temp', 'fsi']),
]


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


def names_to_rows(conn, rec, name):
    """Дээжийн нэрээс мөрийн дугаарыг олно — geo_samples-ийн нэрээр.

    sample_entries.sample_name олонтаа хоосон байдаг тул зөвхөн түүгээр
    хайвал олдохгүй. Программ нь дэлгэцэнд нэрийг geo_samples.sample_name-ээс
    гаргадаг: ";"-ээр тусгаарласан жагсаалт, эсвэл "ROCK-1 - ROCK-30" муж.
    """
    import re
    g = conn.execute('SELECT sample_name, quantity FROM geo_samples WHERE id=?',
                     (rec['geo_sample_id'],)).fetchone()
    if not g or not g['sample_name']:
        return []
    raw = g['sample_name'].strip()
    qty = g['quantity'] or 0
    target = name.strip().lower()

    if ';' in raw:
        parts = [p.strip() for p in raw.split(';') if p.strip()]
        return [i + 1 for i, p in enumerate(parts) if p.lower() == target]

    m = re.match(r'^(.*?)(\d+)\s*[-–]\s*(\d+)\s*$', raw)      # "ROCK-1 - ROCK-30"
    if m:
        pre, a = m.group(1), int(m.group(2))
        return [i + 1 for i in range(qty) if f'{pre}{a + i}'.lower() == target]

    m = re.match(r'^(.*?)(\d+)$', raw)                        # "ROCK-1" → 1,2,3…
    if m:
        pre, a = m.group(1), int(m.group(2))
        return [i + 1 for i in range(qty) if f'{pre}{a + i}'.lower() == target]

    return [i + 1 for i in range(qty)
            if (raw if qty <= 1 else f'{raw}-{i + 1}').lower() == target]


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
            # sample_entries.sample_name олон бичлэгт хоосон байдаг — дэлгэц дээрх
            # нэр нь geo_samples.sample_name дахь ";"-ээр тусгаарласан жагсаалт
            # эсвэл "ROCK-1 - ROCK-30" мужаас гардаг. Программтай ижил аргаар нөхнө.
            nums = names_to_rows(conn, rec, name)
        if not nums:
            print(f'✗ {lab_number} дотор "{name}" нэртэй мөр олдсонгүй.')
            print('  Бүх мөрийг харах бол нэргүйгээр ажиллуулна уу:')
            print(f'    {sys.argv[0]} {lab_number}')
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
        # Бүх шинжилгээний түүхий жин — аль нүд хоосон байгааг шууд харуулна
        for lbl, cols in GROUPS:
            cols = [c for c in cols if c in have]
            if not cols or all(r[c] is None for c in cols):
                continue
            gaps = [c for c in cols if r[c] is None]
            line = '  '.join(f'{c}={"—" if r[c] is None else r[c]}' for c in cols)
            mark = f'   ⚠ дутуу: {", ".join(gaps)}' if gaps else ''
            print(f'      {lbl:12}: {line}{mark}')
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

    # ── Хэмжсэн атлаа тооцоо нь хоосон байгаа эсэх ──
    # "Үр дүнгийн хуудсанд утга алга" гэдгийг DB-ээс шууд шалгана.
    PAIRS = [('Дотоод чийг', ['dc_tare', 'dc_sample', 'dc_dried'], 'mad'),
             ('Үнслэг',      ['ash_tare', 'ash_sample', 'ash_burned'], 'aad'),
             ('Дэгдэмхий',   ['vol_tare', 'vol_sample', 'vol_burned'], 'vad'),
             ('G индекс',    ['g_tare', 'g_coke', 'g_sieve1', 'g_sieve2'], 'g_val')]
    print('\n── Хэмжсэн ч тооцоо нь хоосон байгаа эсэх ──')
    holes = 0
    for r in rows:
        if r['is_duplicate'] != 0:
            continue
        miss = []
        for lbl, raw, calc in PAIRS:
            cols = [c for c in raw if c in have]
            if calc not in have or not cols:
                continue
            if all(r[c] is not None for c in cols) and r[calc] is None:
                miss.append(lbl)
        if miss:
            holes += 1
            print(f'  мөр {r["row_num"]} «{r["sample_name"] or ""}»: '
                  f'{", ".join(miss)} — жин орсон ч үр дүн NULL')
    print('  ✓ ийм зөрчил алга' if not holes else
          f'  ⚠ {holes} мөрөнд жин байгаа ч тооцоо хоосон байна.\n'
          '     Хэмжилтийн хуудсыг нээж "Засах" → "Хадгалах" дарвал дахин бодогдоно.')

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
