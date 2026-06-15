# Хүрэншанд уурхайн лабораторийн удирдлагын систем

Flask + SQLite + Vanilla JS web application for managing coal laboratory analysis workflows.

## Tech Stack

- **Backend**: Python 3, Flask
- **Database**: SQLite via `models.py` (`get_db()`, `init_db()`)
- **Frontend**: Jinja2 templates, Vanilla JS (no framework), Chart.js (CDN when needed)
- **Auth**: Session-based (`session['user_id']`, `session['role']`)
- **File uploads**: `static/uploads/` (photos, PDFs)
- **Export**: `openpyxl` for Excel, `io.BytesIO` for streaming

## Project Structure

```
app.py              # All routes and business logic
models.py           # DB init, get_db(), hash_password(), check_password()
instance/lab.db     # SQLite database (gitignored)
static/
  uploads/          # User photos, device photos, PDFs
  logo.jpg          # Lab logo shown in topbar
templates/
  partial/base.html # Shared layout: topbar, nav, CSS vars, flash messages
  admin/            # dashboard, archive, reports, settings, staff pages
  analysis/         # index, register, receive, measure, result, archive_*
  device/           # list, detail, add, edit
  staff/            # dashboard, detail, profile
  auth/             # login
```

## Auth Decorators

```python
@login_required     # any logged-in user
@admin_required     # role == 'admin'
@senior_required    # role in ('admin', 'senior')
@lab_required       # role in ('admin', 'senior', 'staff')
@preparer_required  # role in ('admin', 'senior', 'preparer')
```

Roles: `admin`, `senior`, `staff`, `preparer`, `geologist`

## Database Schema

### `users`
`id, employee_id, name, position, phone, email, photo, role, password_hash, joined_date, is_active, created_at`

### `geo_samples` — Геологийн дээжийн бүртгэл
`id, sample_name, sample_type (PIT/STOCKPILE/EXPORT/CONTROL/EQ_CONTROL/DP), location, collected_date, quantity, notes, registered_by→users, status (pending/received/prepared/analysing/done), sample_range, created_at`

### `sample_receipt` — Лабораторийн хүлээн авалт
`id, geo_sample_id→geo_samples, lab_number (UNIQUE, e.g. 1046-20260605), lab_serial, received_date, mass_kg, received_by→users, fm_sample_mass, fm_dried_mass, fm_date, fm_operator, mt_tare1/2, mt_sample1/2, mt_dried1/2, mt_crucible1/2, mt_date, mt_shift, mt_operator, prep_status (preparing/ready/done), prep_started_at, prep_done_at, prep_notes, created_at`

### `sample_entries` — Шинжилгээний хэмжилтийн мөр (нэг дээжийн нэг мөр)
`id, receipt_id→sample_receipt, row_num (1..quantity), is_duplicate (0=үндсэн/1=зэрэгцээ), sample_name, mass_kg`

Measurement columns:
- Free moisture: `ff_sample, ff_dried`
- Total moisture: `mt_bux, mt_tare, mt_sample, mt_dried`
- Internal moisture (Mad): `dc_bux, dc_tare, dc_sample, dc_dried`
- Ash (Aad): `ash_tav, ash_tare, ash_sample, ash_burned`
- Volatile (Vad): `vol_tig, vol_tare, vol_sample, vol_burned`
- G-index: `g_tig, g_tare, g_coke, g_sieve1, g_sieve2`
- Other: `sulfur, cal_value, cal_temp, fsi`

Calculated results: `mad, aad, vad, fc`

Workflow: `row_status (empty/done/approved), done_by→users, done_at, approved_by→users, approved_at, updated_by, updated_at, created_at`

UNIQUE constraint: `(receipt_id, row_num, is_duplicate)`

### `qc_settings` — QC зөвшөөрөгдөх зөрүү
`id, parameter (UNIQUE), tolerance, standard, updated_by→users, updated_at`

### `devices`
`id, name, serial_number (UNIQUE), mark_id→device_marks, location, purchase_date, warranty_expiry, calibration_interval, photo, passport_pdf, status (active/repair/standby/archived/replaced), notes, created_at`

### `device_marks`
`id, manufacturer, model, category`

### `calibrations`
`id, device_id→devices, performed_by→users, calibration_date, next_date, result (passed/failed), document, notes, created_at`

### `repairs`
`id, device_id→devices, reported_by→users, reported_date, description, company, repair_date, cost, photo, status (open/in_progress/done/replaced), notes, created_at`

### `device_usage_log`
`id, device_id, user_id, receipt_id, analysis_type (mad/aad/vad/st/q/g/fsi), started_at, ended_at, duration_min, sample_count, notes, created_at`

### `analysis_device_map`
`id, analysis_type, device_id→devices, is_active, updated_by, updated_at`

### `sample_types`
`id, code (UNIQUE), name_mn, name_en, icon, color, serial_from, serial_to, is_pit, is_active, sort_order, created_at`

### `analysis_results` (legacy/unused)
Computed results table — not actively used; results stored directly in `sample_entries`.

## Key Routes

| Route | Auth | Description |
|---|---|---|
| `GET/POST /` | — | Login |
| `GET /dashboard` | login | Admin or staff dashboard |
| `GET /analysis` | login | Analysis list (excludes done) |
| `GET/POST /analysis/register` | lab | Register new geo sample |
| `GET/POST /analysis/receive/<geo_id>` | lab | Receive sample into lab |
| `GET/POST /analysis/measure/<receipt_id>` | lab | Spreadsheet entry |
| `GET /analysis/result/<receipt_id>` | login | Results view + approval |
| `GET /analysis/export/<receipt_id>` | login | Excel export |
| `POST /analysis/row/done` | login | Mark row done |
| `POST /analysis/row/approve` | senior | Approve rows (single/all) |
| `POST /analysis/autosave` | login | Auto-save cell value |
| `POST /analysis/autosave/calc` | login | Save calculated mad/aad/vad/fc |
| `GET /analysis/load/<receipt_id>` | login | Load all entries as JSON |
| `GET /archive` | login | Archive: devices, staff, repairs, done samples |
| `GET /archive/result/<receipt_id>` | login | Archive result view |
| `GET /archive/measure/<receipt_id>` | login | Archive measurement view (read-only) |
| `POST /archive/reopen/<receipt_id>` | senior | Reopen archived analysis |
| `GET /devices` | login | Device list |
| `GET /devices/<did>` | login | Device detail + usage/calibration/repair |
| `GET /reports` | senior | Excel report export |
| `GET /lab-settings` | admin | Settings: lab info, QC, types, device map, profile |
| `POST /lab-settings/qc-delete` | admin | Delete QC parameter |
| `GET /staff` | senior | Staff list |
| `GET /backup` | admin | Download DB backup |

## Analysis Workflow

```
geo_samples.status:  pending → received → prepared → analysing → done
sample_receipt.prep_status:  preparing → ready → done
sample_entries.row_status:   empty → done → approved
```

1. **Register** (`/analysis/register`) — Геолог дээж бүртгэнэ → `geo_samples` үүснэ
2. **Receive** (`/analysis/receive/<geo_id>`) — Лаборант хүлээн авна → `sample_receipt` үүснэ, `geo_samples.status='received'`
3. **Prepare** — Дээж бэлтгэгч `prep_start/prep_done` дуудна → `status='prepared'→'ready'`
4. **Measure** (`/analysis/measure/<receipt_id>`) — Химич хүснэгтэд утга оруулна, autosave, calc
5. **Done** — Мөр бүрт `row_done` → `row_status='done'`, `geo_samples.status='analysing'`
6. **Approve** (`/analysis/row/approve`) — Senior/Admin баталгаажуулна → `row_status='approved'`
7. **Complete** — Бүх мөр approved → `geo_samples.status='done'`, `prep_status='done'` → архивт орно

## Calculation Formulas (calculate_results in app.py)

```python
mad = (dc_tare + dc_sample - dc_dried) / dc_sample * 100
aad = (ash_burned - ash_tare) / ash_sample * 100
vad = (vol_tare + vol_sample - vol_burned) / vol_sample * 100 - mad
fc  = 100 - mad - aad - vad
```

QC check: `|primary - duplicate| <= tolerance` for each parameter (from `qc_settings`).

## Lab Number Format

`generate_lab_number(sample_type, date_str)` → e.g. `1046-20260605`
- Serial from `sample_types.serial_from/serial_to` range
- Increments from last used serial in `sample_receipt`

## Frontend Patterns

- All pages extend `templates/partial/base.html`
- CSS variables in `:root`: `--navy`, `--teal`, `--coral`, `--amber`, `--purple`, `--gray`
- Common classes: `.card`, `.btn`, `.btn-primary/.teal/.danger/.ghost/.sm`, `.badge`, `.table`, `.stat-grid/.stat-card`, `.form-input/.form-label/.form-group`, `.alert-success/.alert-error`
- Tab switching pattern (settings, archive): `.tab-pane{display:none!important}` + `.tab-pane.active{display:block!important}` + `switchTab(btn, tabId)` sets both `.classList` and `style.display`
- Language: `session.get('lang','mn')`, toggle via `/lang/<lang>?next=<url>`
- Flash messages: `flash('msg', 'success'|'error')`, rendered in base.html

## measure.html Specifics

- `border-collapse:separate` + sticky headers for freeze effect
- Column groups: `.cg-ff`, `.cg-mt`, `.cg-dc`, `.cg-un`, `.cg-db`, `.cg-gi`, `.cg-st`, `.cg-il`, `.cg-fsi` — toggled with `.hide` class
- Keyboard nav: Arrow keys, Tab, Enter — move between visible inputs
- Auto-save on `blur` via `POST /analysis/autosave`
- Calc on `input` event — updates `calc-cell` spans
- Duplicate rows: `.dup-row` toggled with `.show` class via `toggleDup(ri)`
- Mouse drag: `mousemove` on `sheetWrap` focuses hovered input

## Completed Features

- [x] Auth: login/logout, role-based access
- [x] Dashboard: stats, expiring calibrations, open repairs
- [x] Analysis full workflow: register → receive → prepare → measure → approve → archive
- [x] Spreadsheet measure.html: keyboard nav, autosave, QC color highlight, column toggle, drag select, decimal buttons
- [x] Analysis result page: progress bar, approve selected/all, Excel export
- [x] Archive pages: archive_result.html (results view), archive_measure.html (read-only spreadsheet), reopen
- [x] Device management: CRUD, calibration, repair, usage log, archive/restore
- [x] Staff management: CRUD, activate/deactivate, profile
- [x] QC settings: per-parameter tolerance + standard, add/delete
- [x] Lab settings: lab info, logo, sample types, device map
- [x] Reports: Excel export (4 sheets)
- [x] Archive page: tabbed view for devices/staff/repairs/analysis
- [x] DB backup download

## Coding Rules

- Do not break existing routes or rename functions — other templates depend on `url_for('route_name')`
- `get_db()` returns a `sqlite3.Row`-factory connection — always call `conn.close()` after use
- `session['user_id']`, `session['role']` — set on login, cleared on logout
- `current_user` is injected via `@app.context_processor` (`inject_user`) — available in all templates
- Flash categories must be `'success'` or `'error'` — base.html maps to `.alert-success/.alert-error`
- `sample_entries` autosave accepts one field at a time: `{receipt_id, row_num, is_duplicate, field, value}`
- `qc_settings.parameter` has UNIQUE constraint — use `INSERT OR IGNORE` or catch exception
- `geo_samples.status='done'` hides sample from active analysis list (filtered in `/analysis` route)
- Always check `sample_entries.is_duplicate` — 0=primary, 1=parallel; QC compares the two
- Branch for all development: `claude/adoring-hamilton-wdvj0b`
