#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Төхөөрөмжийн шалгалтын давтамж/загварыг зөв болгох нэг удаагийн засвар."""
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), 'instance', 'lab.db')
c = sqlite3.connect(DB)
cur = c.cursor()

# 1) Анхдагч: бүгдийг өдөр бүрийн шалгалт болгоно
cur.execute("UPDATE devices SET check_freq='daily'")

# 2) Калориметр (Илчлэг), Хүхэр — сарын шалгалт
cur.execute("""UPDATE devices SET check_freq='monthly'
    WHERE LOWER(name) LIKE '%калориметр%'
       OR LOWER(name) LIKE '%илчлэг%'
       OR LOWER(name) LIKE '%хүхэр%'
       OR LOWER(name) LIKE '%sulfur%'""")

# 3) Холигч, Хөөлтийн зэрэг тодорхойлох багаж — 7 хоногийн шалгалт
cur.execute("""UPDATE devices SET check_freq='weekly'
    WHERE LOWER(name) LIKE '%холигч%'
       OR LOWER(name) LIKE '%хөөлт%'""")

# 4) Жин (аналитик/техник/электрон) — өдөр бүр, босоо жингийн загвар
cur.execute("""UPDATE devices SET check_group1='Туухай', check_group1_cols=0
    WHERE LOWER(name) LIKE '%жин%'""")

c.commit()

print('=== Одоогийн төлөв ===')
cur.row_factory = sqlite3.Row
for r in c.execute("""SELECT name, check_freq, check_group1_cols
    FROM devices WHERE status NOT IN ('archived','replaced','decommissioned')
    ORDER BY lab_id"""):
    print(r[0], '|', r[1], '| cols', r[2])
c.close()
print('=== Дууслаа ===')
