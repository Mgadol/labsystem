"""Хэмжилтийн утга хэзээ, хэн, юуг арилгасныг харуулна.

value_audit хүснэгтээс уншина — утгатай байсан талбар өөрчлөгдөх бүрд
хуучин утга нь бичигдэж үлддэг.

Хэрэглээ (серверт):
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_audit.py
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_audit.py --cleared
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_audit.py 2164-20260730
    /opt/labsystem/venv/bin/python3 /opt/labsystem/tools/check_audit.py --restore 42

  --cleared    зөвхөн ХОOСРУУЛСАН (утга нь устсан) тохиолдлыг харуулна
  --restore N  тухайн бүртгэлийн хуучин утгыг буцааж тавина
"""
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'instance', 'lab.db')

FIELD_MN = {
    'ff_sample': 'ЧЧ дээж', 'ff_dried': 'ЧЧ хатаасан',
    'mt_tare': 'НЧ хоосон бюкс', 'mt_sample': 'НЧ дээж', 'mt_dried': 'НЧ хатаасан',
    'dc_tare': 'ДЧ хоосон бюкс', 'dc_sample': 'ДЧ дээж', 'dc_dried': 'ДЧ хатаасан',
    'ash_tare': 'Үнс хоосон', 'ash_sample': 'Үнс дээж', 'ash_burned': 'Үнс шатаасан',
    'vol_tare': 'ДБ хоосон тигель', 'vol_sample': 'ДБ дээж', 'vol_burned': 'ДБ шатаасан',
    'g_tare': 'G хоосон', 'g_coke': 'G кокс', 'g_sieve1': 'G шигшүүр1',
    'g_sieve2': 'G шигшүүр2', 'sulfur': 'Хүхэр', 'cal_value': 'Илчлэг', 'fsi': 'ЧХЗ',
}


def restore(conn, aid):
    a = conn.execute('SELECT * FROM value_audit WHERE id=?', (aid,)).fetchone()
    if not a:
        print(f'✗ {aid} дугаартай бүртгэл олдсонгүй.')
        return 1
    cols = {r[1] for r in conn.execute('PRAGMA table_info(sample_entries)')}
    if a['field'] not in cols:
        print(f'✗ "{a["field"]}" багана байхгүй.')
        return 1
    cur = conn.execute(
        f'SELECT {a["field"]} AS v FROM sample_entries '
        f'WHERE receipt_id=? AND row_num=? AND is_duplicate=?',
        (a['receipt_id'], a['row_num'], a['is_duplicate'])).fetchone()
    if not cur:
        print('✗ Мөр олдсонгүй.')
        return 1
    print(f'  {a["field"]}: одоо {cur["v"]!r}  →  сэргээх {a["old_value"]!r}')
    conn.execute(
        f'UPDATE sample_entries SET {a["field"]}=? '
        f'WHERE receipt_id=? AND row_num=? AND is_duplicate=?',
        (a['old_value'], a['receipt_id'], a['row_num'], a['is_duplicate']))
    conn.commit()
    print('✓ Сэргээлээ. Хэмжилтийн хуудсыг нээж тооцоог шалгана уу.')
    return 0


def main():
    args = list(sys.argv[1:])
    only_cleared = '--cleared' in args
    if only_cleared:
        args.remove('--cleared')
    if '--restore' in args:
        i = args.index('--restore')
        aid = args[i + 1] if i + 1 < len(args) else None
        if not (aid or '').isdigit():
            print('✗ --restore-д бүртгэлийн дугаар өгнө үү.')
            return 1
        conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row
        rc = restore(conn, int(aid)); conn.close()
        return rc
    lab_number = args[0] if args else None

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    if not conn.execute("SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name='value_audit'").fetchone():
        print('value_audit хүснэгт хараахан үүсээгүй байна — программыг шинэчилж,')
        print('дахин ачаалсны дараа өөрчлөлт бүр бүртгэгдэж эхэлнэ.')
        conn.close()
        return 0

    q = """SELECT va.*, sr.lab_number, u.name AS who
             FROM value_audit va
             LEFT JOIN sample_receipt sr ON sr.id = va.receipt_id
             LEFT JOIN users u ON u.id = va.user_id"""
    where, params = [], []
    if only_cleared:
        where.append('va.new_value IS NULL')
    if lab_number:
        where.append('sr.lab_number = ?')
        params.append(lab_number)
    if where:
        q += ' WHERE ' + ' AND '.join(where)
    q += ' ORDER BY va.at DESC LIMIT 200'
    rows = conn.execute(q, params).fetchall()
    conn.close()

    if not rows:
        print('Бүртгэл алга — утга арилсан/өөрчлөгдсөн тохиолдол олдсонгүй.')
        return 0

    print(f'{"ХООСРУУЛСАН" if only_cleared else "Утга өөрчлөгдсөн"}: '
          f'{len(rows)} бүртгэл (сүүлийн 200)\n')
    print(f'{"№":>5}  {"Огноо/цаг":19} {"Ажил":16} {"мөр":>4} {"төрөл":9} '
          f'{"талбар":18} {"хуучин":>10} → {"шинэ":<10} хэн')
    for r in rows:
        dup = ('үндсэн' if r['is_duplicate'] == 0 else
               'зэрэгцээ' if r['is_duplicate'] == 1 else f'давт{r["is_duplicate"]}')
        fld = FIELD_MN.get(r['field'], r['field'])
        new = '—(хоосон)' if r['new_value'] is None else r['new_value']
        print(f'{r["id"]:>5}  {(r["at"] or "")[:19]:19} {r["lab_number"] or "?":16} '
              f'{r["row_num"]:>4} {dup:9} {fld:18} {r["old_value"] or "":>10} → '
              f'{new:<10} {r["who"] or ""}')
    print()
    print('Хоосруулсан бүртгэлийг буцаах бол:')
    print('    check_audit.py --restore <№>')
    return 0


if __name__ == '__main__':
    sys.exit(main())
