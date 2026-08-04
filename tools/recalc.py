"""Жин орсон атлаа тооцоо нь хоосон мөрүүдийг дахин бодож хадгална.

Хэмжилтийн хуудас тооцоог ХӨТӨЧ дээрээ бодож харуулдаг бол үр дүнгийн
хуудас DB-д ХАДГАЛАГДСАН утгыг уншдаг. Тиймээс жин нь байгаа ч тооцоо нь
NULL үлдсэн мөр хэмжилтийн хуудсанд харагдаад үр дүнгийн хуудсанд гарахгүй
байдалд хүрнэ. Энэ скрипт тэр зөрүүг арилгана.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/recalc.py                # зөвхөн харах
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/recalc.py --fix          # бүгдийг засах
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/recalc.py 7008-20260730 --fix

ЗӨВХӨН ХООСОН талбарыг бөглөнө — байгаа утгыг хэзээ ч дарж бичихгүй.
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')


def num(v):
    try:
        return float(v) if v is not None and v != '' else None
    except (TypeError, ValueError):
        return None


def calc_mad(r):
    t, s, d = num(r['dc_tare']), num(r['dc_sample']), num(r['dc_dried'])
    if t is None or d is None or not s:
        return None
    return (t + s - d) / s * 100


def calc_aad(r):
    t, s, b = num(r['ash_tare']), num(r['ash_sample']), num(r['ash_burned'])
    if t is None or b is None or not s:
        return None
    return (b - t) / s * 100


def calc_vad(r, mad):
    t, s, b = num(r['vol_tare']), num(r['vol_sample']), num(r['vol_burned'])
    if t is None or b is None or not s or mad is None:
        return None
    return (t + s - b) / s * 100 - mad


def calc_g(r):
    """G = 10 + (30×(m3−m1) + 70×(m4−m1)) / (m2−m1)"""
    m1, m2 = num(r['g_tare']), num(r['g_coke'])
    m3, m4 = num(r['g_sieve1']), num(r['g_sieve2'])
    if None in (m1, m2, m3, m4) or (m2 - m1) <= 0:
        return None
    return 10 + (30 * (m3 - m1) + 70 * (m4 - m1)) / (m2 - m1)


def main():
    args = [a for a in sys.argv[1:] if a != '--fix']
    fix = '--fix' in sys.argv
    lab = args[0] if args else None

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    q = """SELECT se.*, sr.lab_number FROM sample_entries se
           JOIN sample_receipt sr ON sr.id=se.receipt_id"""
    p = []
    if lab:
        q += ' WHERE sr.lab_number=?'
        p.append(lab)
    q += ' ORDER BY se.receipt_id, se.row_num, se.is_duplicate'
    rows = conn.execute(q, p).fetchall()
    if not rows:
        print(f'✗ {"«" + lab + "» ажил олдсонгүй" if lab else "мөр алга"}.')
        conn.close()
        return

    # Зэрэгцээ мөрийн Vad-д үндсэн мөрийн Mad хэрэгтэй
    primary_mad = {}
    for r in rows:
        if r['is_duplicate'] == 0:
            primary_mad[(r['receipt_id'], r['row_num'])] = (
                num(r['mad']) if r['mad'] is not None else calc_mad(r))

    todo = []
    for r in rows:
        mad_now = num(r['mad'])
        own_mad = mad_now if mad_now is not None else calc_mad(r)
        base_mad = own_mad if own_mad is not None else \
            primary_mad.get((r['receipt_id'], r['row_num']))
        upd = {}
        if r['mad'] is None and calc_mad(r) is not None:
            upd['mad'] = calc_mad(r)
        if r['aad'] is None and calc_aad(r) is not None:
            upd['aad'] = calc_aad(r)
        if r['vad'] is None and calc_vad(r, base_mad) is not None:
            upd['vad'] = calc_vad(r, base_mad)
        if 'g_val' in r.keys() and r['g_val'] is None and calc_g(r) is not None:
            upd['g_val'] = calc_g(r)
        # FC — Mad/Aad/Vad гурвуулаа мэдэгдэж байж бодогдоно
        m = upd.get('mad', num(r['mad']))
        a = upd.get('aad', num(r['aad']))
        v = upd.get('vad', num(r['vad']))
        if r['fc'] is None and None not in (m, a, v):
            upd['fc'] = 100 - m - a - v
        if upd:
            todo.append((r, upd))

    if not todo:
        print('✓ Жин орсон атлаа тооцоо нь хоосон мөр алга — бүх зүйл цэгцтэй.')
        conn.close()
        return

    dup = {0: 'үндсэн', 1: 'зэрэгцээ'}
    print(f'{"Засах" if fix else "Олдсон"} мөр: {len(todo)}\n')
    for r, upd in todo:
        d = dup.get(r['is_duplicate'], f'давталт {r["is_duplicate"]}')
        vals = '  '.join(f'{k}={v:.2f}' for k, v in sorted(upd.items()))
        print(f'  {r["lab_number"]:22} мөр {r["row_num"]:<3} {d:10} → {vals}')

    if not fix:
        print('\nЗасахгүй — зөвхөн жагсаалт. Засахын тулд --fix нэмнэ үү.')
        conn.close()
        return

    for r, upd in todo:
        sets = ', '.join(f'{k}=?' for k in sorted(upd))
        conn.execute(f'UPDATE sample_entries SET {sets} WHERE id=?',
                     [upd[k] for k in sorted(upd)] + [r['id']])
    conn.commit()
    conn.close()
    print(f'\n✓ {len(todo)} мөрийн тооцоо хадгалагдлаа. '
          'Үр дүнгийн хуудсыг дахин нээхэд утга гарна.')


if __name__ == '__main__':
    main()
