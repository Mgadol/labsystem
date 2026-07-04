#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Төхөөрөмжийн шалгалтын давтамж/загварыг зөв болгох нэг удаагийн засвар.
Python-ы substring харьцуулалт ашигласан (SQL LIKE-аас найдвартай)."""
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), 'instance', 'lab.db')
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

MONTHLY = ['калориметр', 'илчлэг', 'хүхэр', 'хихэр', 'sulfur']
WEEKLY  = ['холигч', 'хоолт', 'хөөлт', 'зэрэг тодорхойлох', 'mixer']

rows = c.execute("SELECT id, name FROM devices").fetchall()
n_daily = n_weekly = n_monthly = n_weight = 0
for r in rows:
    nm = (r['name'] or '').lower()
    if any(k in nm for k in MONTHLY):
        freq = 'monthly'; n_monthly += 1
    elif any(k in nm for k in WEEKLY):
        freq = 'weekly'; n_weekly += 1
    else:
        freq = 'daily'; n_daily += 1
    c.execute("UPDATE devices SET check_freq=? WHERE id=?", (freq, r['id']))
    if 'жин' in nm:
        c.execute("UPDATE devices SET check_group1='Туухай', check_group1_cols=0 WHERE id=?", (r['id'],))
        n_weight += 1
# Автомат тохиргоо дахин ажиллахгүй болгоно (restart хийхэд энэ тохиргоо хадгалагдана)
c.execute("PRAGMA user_version=1")
c.commit()

print(f'daily={n_daily}  weekly={n_weekly}  monthly={n_monthly}  жин(cols=0)={n_weight}')
print('=== Төлөв ===')
for r in c.execute("""SELECT name, check_freq, check_group1_cols
    FROM devices WHERE status NOT IN ('archived','replaced','decommissioned')
    ORDER BY lab_id"""):
    print(r[0], '|', r[1], '| cols', r[2])
c.close()
print('=== Дууслаа ===')
