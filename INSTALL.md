# Суулгах заавар

Лабораторийн удирдлагын системийг шинэ лабораторид суулгах алхмууд.

## Шаардлага

| Зүйл | Хамгийн бага |
|---|---|
| Үйлдлийн систем | Ubuntu 22.04 / Debian 12 (эсвэл Linux) |
| Python | 3.10+ |
| RAM | 1 GB |
| Диск | 10 GB (дээжийн зураг, PDF-ийн хэрээр өснө) |
| Хэрэглэгчийн тал | Chrome эсвэл Edge хөтөч — суулгах программгүй |

Мэдээллийн сан нь SQLite тул тусдаа сервер, лиценз, админ шаардахгүй.

---

## 1. Код татах

**Заавал `main` салбараас** татна. `main` бол турших шатны код биш, тогтвортой
хувилбар.

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
sudo git clone -b main https://github.com/Mgadol/labsystem /opt/labsystem
cd /opt/labsystem
```

## 2. Виртуал орчин, сангууд

```bash
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
```

## 3. Эхний ажиллуулалт

```bash
venv/bin/python3 app.py
```

Эхний ажиллуулалтад дараах зүйл **автоматаар** үүснэ:

- `instance/lab.db` — хоосон мэдээллийн сан, бүх хүснэгттэй
- `instance/secret_key` — тухайн суулгацын өөрийн нууц түлхүүр
- Админ хэрэглэгч: **ADMIN / admin123**

> Өмнөх лабораторийн ямар ч өгөгдөл дагаж ирэхгүй. `instance/` болон
> `static/uploads/` нь gitignore-т орсон.

Хөтчөөр `http://<сервер>:5000` хаягаар нэвтэрч шалгана.

## 4. Systemd үйлчилгээ болгох

```bash
sudo tee /etc/systemd/system/labsystem.service > /dev/null <<'EOF'
[Unit]
Description=Лабораторийн удирдлагын систем
After=network.target

[Service]
WorkingDirectory=/opt/labsystem
ExecStart=/opt/labsystem/venv/bin/python3 /opt/labsystem/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now labsystem
sudo systemctl status labsystem
```

## 5. Заавал хийх тохиргоо

Админаар нэвтэрсний дараа:

1. **Нууц үг солих** — `admin123` анхдагчийг заавал өөрчилнө
2. **Тохиргоо → Лабораторийн мэдээлэл** — лабораторийн нэр (монгол, англи), лого
3. **Тохиргоо → Дээжийн төрөл** — тухайн лабораторийн төрлүүд ба ажлын дугаарын муж
4. **Тохиргоо → QC** — үзүүлэлт тус бүрийн зөвшөөрөгдөх зөрүү, мөрдөх стандарт
5. **Ажилтан** — хэрэглэгч бүртгэж, дүр ба эрх олгох
6. **Төхөөрөмж** — багаж бүртгэж, калибровкын хугацаа оруулах

Код өөрчлөх шаардлагагүй — бүгд дэлгэцээс тохируулагдана.

### Дүрүүд

`admin` · `senior` (ахлах химич) · `staff` (химич) · `preparer` (дээж бэлтгэгч) ·
`geologist` · `bayjuulach` (баяжуулагч) · `guest` (зочин)

Эдгээр дээр нэмж хүн тус бүрт: баталгаажуулах, тайлан гаргах, үр дүн харах,
экспортлох, дахин нээх эрхийг тусад нь олгоно.

---

## Шинэчлэлт

```bash
cd /opt/labsystem && git pull && sudo systemctl restart labsystem
```

Мэдээллийн сангийн шинэ хүснэгт, багана **автоматаар нэмэгдэнэ**
(`ensure_tables()` эхлэхэд ажиллана). Гараар юу ч хийх шаардлагагүй.

> **Чухал:** засварыг сервер дээр шууд хийж болохгүй. Дараагийн `git pull`
> тэр өөрчлөлтийг дарж устгана, мөн бусад лабораторид хүрэхгүй. Оношилгоог
> серверт хийж болох ч, **засвар нь гитээс явах ёстой**.

## Нөөцлөлт

Хамгийн чухал файл бол `instance/lab.db`. Мөн `static/uploads/`
(зураг, PDF) болон `instance/settings.json`.

```bash
# Гараар
cp /opt/labsystem/instance/lab.db ~/lab_$(date +%F).db

# Өдөр бүр 02:00 цагт
echo '0 2 * * * cp /opt/labsystem/instance/lab.db /var/backups/lab_$(date +\%F).db' \
  | sudo crontab -
```

Систем дотроос ч **Тохиргоо → Нөөцлөлт** хэсгээс татаж авч болно.

## Түгээмэл асуудал

| Шинж тэмдэг | Шалтгаан ба шийдэл |
|---|---|
| `git pull` — *Your local changes would be overwritten* | Сервер дээр гит-д бүртгэлтэй файл өөрчлөгдсөн. `git status` -аар олж, `git checkout -- <файл>` хийнэ |
| Толгойд «Лабораторийн нэр» гэж гарна | Тохиргоо → Лабораторийн мэдээлэл дээрээс нэрээ бичээгүй байна |
| Хуудас нээгдэхгүй | `sudo systemctl status labsystem` ба `journalctl -u labsystem -n 50` |
| Excel тайлан дээр лого гарахгүй | Тохиргооноос лого ачаална |

---

## Юу шилжиж, юу шилжихгүй вэ

| Шилжинэ (гитээр) | Шилжихгүй (тухайн лабораторийнх) |
|---|---|
| Программын код, загварууд | `instance/lab.db` — бүх шинжилгээний өгөгдөл |
| Анхдагч саармаг лого | `instance/settings.json` — нэр, лого |
| Заавар, хэрэгслүүд | `instance/secret_key` |
| | `static/uploads/` — зураг, PDF, ачаалсан лого |
