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
- Админ хэрэглэгч **ADMIN**, түүнд зориулсан **санамсаргүй нууц үг**

Нууц үг консол дээр тодоор хэвлэгдэнэ. Мөн `instance/ADMIN_PASSWORD.txt`
дотор үлдэнэ — эхний нэвтрэлтийн дараа нууц үгээ солиод **тэр файлыг устгана**.

> Өмнөх лабораторийн ямар ч өгөгдөл дагаж ирэхгүй. `instance/` болон
> `static/uploads/` нь gitignore-т орсон.

Хөтчөөр `http://<сервер>:5000` хаягаар нэвтэрч шалгана.

## 4. Systemd үйлчилгээ болгох

`HTTPS_ENABLED` — доорх «HTTPS» хэсгийг үзнэ үү. Дотоод сүлжээнд л
ажиллах бол `false` үлдээж болно.

```bash
sudo tee /etc/systemd/system/labsystem.service > /dev/null <<'EOF'
[Unit]
Description=Лабораторийн удирдлагын систем
After=network.target

[Service]
WorkingDirectory=/opt/labsystem
ExecStart=/opt/labsystem/venv/bin/python3 /opt/labsystem/app.py
Environment=HTTPS_ENABLED=false
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now labsystem
sudo systemctl status labsystem
```

## 4a. HTTPS — интернэтэд гаргах бол ЗААВАЛ

Систем нь HTTPS-ийг өөрөө хийхгүй. Домэйнээр интернэтээс хандах бол
урд нь nginx тавьж, гэрчилгээ авна:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo tee /etc/nginx/sites-available/labsystem > /dev/null <<'EOF'
server {
    server_name lab.example.mn;
    client_max_body_size 20M;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/labsystem /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d lab.example.mn
```

Дараа нь **заавал** systemd дотор асаана:

```bash
sudo sed -i 's/HTTPS_ENABLED=false/HTTPS_ENABLED=true/' \
  /etc/systemd/system/labsystem.service
sudo systemctl daemon-reload && sudo systemctl restart labsystem
```

> **Яагаад чухал вэ:** `HTTPS_ENABLED=true` үед сешн күүки `Secure`
> тэмдэгтэй явна. Тавихгүй бол күүки шифрлэгдээгүй холболтоор дамжиж,
> нэг сүлжээнд байгаа хүн түүнийг хулгайлж хэн нэгний эрхээр нэвтрэх
> боломжтой. `tools/healthcheck.py` энэ тохиргоог шалгаж сануулна.

## 5. Заавал хийх тохиргоо

Админаар нэвтэрсний дараа:

1. **Нууц үг солих**, дараа нь `instance/ADMIN_PASSWORD.txt`-ийг устгах
2. **Тохиргоо → Лабораторийн мэдээлэл** — лабораторийн нэр, лого
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
/opt/labsystem/venv/bin/python3 tools/healthcheck.py
```

Мэдээллийн сангийн шинэ хүснэгт, багана **автоматаар нэмэгдэнэ**
(`ensure_tables()` эхлэхэд ажиллана). Гараар юу ч хийх шаардлагагүй.

`healthcheck.py` нь шинэчлэлт бүрэн буусныг батална: хувилбар, гит дэх
байрлал, шилжилт эцэс хүртэл ажилласан эсэх, дутуу хүснэгт/багана,
мэдээллийн сангийн бүрэн бүтэн байдал, нөөцлөлт, аюулгүй байдлын
тохиргоо. Асуудал илэрвэл гарах код **1** буцаана.

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
