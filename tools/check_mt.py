"""Нийт чийг (Mt) ХАСАХ гарсан мөрүүдийг олж, шалтгааныг оношилно.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_mt.py
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_mt.py 2164-20260730

Дугаар өгвөл зөвхөн тухайн ажлыг, өгөхгүй бол бүх ажлыг шалгана.

Mt-ийн томьёо:
    чөлөөт чийг  ЧЧ    = (ff_sample − ff_dried) / ff_sample × 100
    үлдэгдэл     Mt_үл = (mt_tare + mt_sample − mt_dried) / mt_sample × 100
    нийт         Mt    = ЧЧ + Mt_үл × (1 − ЧЧ/100)

Mt хасах гарах ГАНЦ шалтгаан бол дээрх хоёрын аль нэг нь хасах болох:
  • mt_dried > mt_tare + mt_sample  → хатаасны дараах масс нь эхнийхээс их
  • ff_dried > ff_sample            → чөлөөт чийгийн хатаасан масс нь их
Хоёулаа физикийн хувьд боломжгүй тул жин буруу/дутуу орсон гэсэн үг.
"""
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, 'instance', 'lab.db')


def label(d):
    return 'үндсэн' if d == 0 else 'зэрэгцээ' if d == 1 else f'давталт {d}'


def f(v, n=4):
    return '—' if v is None else format(v, f'.{n}f').rstrip('0').rstrip('.')


def parts(r):
    """(ЧЧ, Mt_үлдэгдэл, Mt_нийт) — аль нь ч бодогдохгүй бол None"""
    fs, fd = r['ff_sample'], r['ff_dried']
    chch = ((fs - fd) / fs * 100) if (fs and fs > 0 and fd is not None) else 0
    mtt, mts, mtd = r['mt_tare'], r['mt_sample'], r['mt_dried']
    if mtt is None or not mts or mts <= 0 or mtd is None:
        return chch, None, None
    raw = (mtt + mts - mtd) / mts * 100
    return chch, raw, (chch + raw * (1 - chch / 100)) if chch else raw


def diagnose(r, chch, raw):
    """Яагаад хасах гарсныг тайлбарлана"""
    out = []
    mtt, mts, mtd = r['mt_tare'], r['mt_sample'], r['mt_dried']
    if raw is not None and raw < 0:
        over = mtd - (mtt + mts)
        out.append(f'хатаасны дараах масс {f(mtd)} нь (хоосон бюкс {f(mtt)} + '
                   f'дээж {f(mts)} = {f(mtt + mts)})-ээс {f(over)} гр-аар ИХ')
        # Хамгийн түгээмэл гурван алдааг шалгана
        if mts and abs(mtd - (mtt + mts)) > mts:
            out.append('  → "Дээж масс" эсвэл "Хоосон бюкс" багана дутуу/буруу '
                       'орсон бололтой')
        if mtt is not None and mts and mtd is not None and mtd < mts:
            out.append('  → хатаасны дараах массыг БЮКСГҮЙГЭЭР бичсэн байж '
                       'магадгүй (бусад багана нь бюкстэй)')
        if mtt is not None and mtd is not None and mtt > mtd:
            out.append('  → "Хоосон бюкс" ба "Хатаасны дараах масс" солигдсон '
                       'байж магадгүй')
    if chch and chch < 0:
        out.append(f'чөлөөт чийг ХАСАХ ({f(chch, 2)}%): хатаасан масс '
                   f'{f(r["ff_dried"])} > дээжийн масс {f(r["ff_sample"])}')
        out.append('  → ЧЧ-ийн хоёр багана солигдсон байж магадгүй')
    return out


def main():
    lab_number = sys.argv[1] if len(sys.argv) > 1 else None
    if not os.path.exists(DB):
        print(f'✗ DB олдсонгүй: {DB}')
        return 1
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    q = """SELECT sr.lab_number, sr.received_date, se.*
             FROM sample_entries se
             JOIN sample_receipt sr ON sr.id = se.receipt_id"""
    args = []
    if lab_number:
        q += ' WHERE sr.lab_number = ?'
        args.append(lab_number)
    q += ' ORDER BY sr.received_date DESC, sr.lab_number, se.row_num, se.is_duplicate'
    rows = conn.execute(q, args).fetchall()
    conn.close()

    if lab_number and not rows:
        print(f'✗ "{lab_number}" дугаартай ажил олдсонгүй.')
        return 1

    bad, measured, jobs = [], 0, set()
    for r in rows:
        chch, raw, mt = parts(r)
        if mt is None and not chch:
            continue
        measured += 1
        if (mt is not None and mt < 0) or (raw is not None and raw < 0) or chch < 0:
            bad.append((r, chch, raw, mt))
            jobs.add(r['lab_number'])

    print(f'Нийт чийг хэмжсэн мөр: {measured}')
    if not bad:
        print('✓ Хасах утга алга — бүх Mt эерэг байна.')
        return 0

    print(f'⚠ ХАСАХ гарсан мөр: {len(bad)} ({len(jobs)} ажилд)\n')
    cur = None
    for r, chch, raw, mt in bad:
        if r['lab_number'] != cur:
            cur = r['lab_number']
            print(f'══ {cur}  ({r["received_date"] or "огноогүй"}) ══')
        print(f'  мөр {r["row_num"]} «{r["sample_name"] or ""}» — {label(r["is_duplicate"])} '
              f'[{r["row_status"]}]')
        print(f'      ЧЧ  : дээж={f(r["ff_sample"])}  хатаасан={f(r["ff_dried"])}'
              f'   → {f(chch, 2)}%')
        print(f'      НЧ  : бюкс№={r["mt_bux"] or "—"}  хоосон={f(r["mt_tare"])}  '
              f'дээж={f(r["mt_sample"])}  хатаасны дараах={f(r["mt_dried"])}')
        print(f'      Mt  : үлдэгдэл {f(raw, 2)}%   НИЙТ {f(mt, 2)}%')
        for line in diagnose(r, chch, raw):
            print(f'      ⚠ {line}')
        if r['updated_at']:
            print(f'      сүүлд зассан: {r["updated_at"]}')
        print()

    print('── Дүгнэлт ──')
    print('Хасах Mt бол тооцооны алдаа БИШ — оруулсан жин буруу гэсэн үг.')
    print('Хэмжилтийн хуудсыг нээж, дээрх мөрүүдийн жинг тэмдэглэлтэй нь')
    print('тулгаж засна уу. Зассан даруйд улаан өнгө арилна.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
