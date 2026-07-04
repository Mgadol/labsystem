# ═══════════════════════════════════════════════════════════
#  ХҮРЭНШАНД РЕСТОРАН — Дижитал меню апп
#  Лабораторийн системээс БҮРЭН ТУСДАА бие даасан програм.
#  Ажиллуулах:  python app.py  →  http://localhost:5001
# ═══════════════════════════════════════════════════════════
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
import os, sqlite3, uuid, secrets

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, 'instance', 'restaurant.db')
UPLOAD_DIR = os.path.join(BASE, 'static', 'uploads')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

# Secret key — instance/-д автоматаар үүсч хадгалагдана
_KEY_FILE = os.path.join(BASE, 'instance', 'secret_key')
os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
if os.path.exists(_KEY_FILE):
    app.secret_key = open(_KEY_FILE, 'rb').read()
else:
    _k = secrets.token_bytes(32)
    open(_KEY_FILE, 'wb').write(_k)
    app.secret_key = _k

# Админ нууц үг (орчны хувьсагчаар солино: RESTO_ADMIN_PASS)
ADMIN_PASSWORD = os.environ.get('RESTO_ADMIN_PASS', 'resto123')

RESTAURANT = {
    'name':    'Хүрэншанд',
    'name_en': 'KHURENSHAND',
    'tagline': 'Restaurant & Lounge',
    'hours':   '11:00 – 23:00',
    'phone':   '7570-1000',
}

CATEGORIES = [
    ('starter',  'Зууш',          'Starters',     '🥟'),
    ('salad',    'Салат',         'Salads',       '🥗'),
    ('soup',     'Шөл',           'Soups',        '🍜'),
    ('main',     'Үндсэн хоол',   'Main Courses', '🍖'),
    ('national', 'Үндэсний хоол', 'Mongolian',    '🥘'),
    ('grill',    'Гриль & BBQ',   'Grill & BBQ',  '🔥'),
    ('side',     'Гарнир',        'Sides',        '🍚'),
    ('dessert',  'Амттан',        'Desserts',     '🍰'),
    ('drink',    'Ундаа',         'Beverages',    '🥤'),
    ('hotdrink', 'Кофе & Цай',    'Coffee & Tea', '☕'),
]

TAGS = [
    ('special', 'Тогоочийн санал', '⭐'),
    ('new',     'Шинэ',            '✨'),
    ('spicy',   'Халуун ногоотой', '🌶️'),
    ('veg',     'Цагаан хоолтон',  '🌿'),
]

# (category, нэр, name_en, тайлбар, найрлага, порц, үнэ, ккал, tags)
SEED_DISHES = [
    # ── ЗУУШ ──
    ('starter', 'Брускетта', 'Bruschetta',
     'Шаргал болтол шарсан багет дээр анхилуун базилик, шинэ улаан лооль, сармисаар амталсан сонгодог итали зууш.',
     'Багет, улаан лооль, базилик, сармис, оливын тос, бальзамик', '180 гр', 9900, 280, 'veg'),
    ('starter', 'Моцарелла савх', 'Mozzarella Sticks',
     'Гадуураа шаржигнасан, дотроо уян сунадаг моцарелла — улаан лоолийн халуун сүмстэй.',
     'Моцарелла бяслаг, талх дурс, улаан лоолийн сүмс', '200 гр', 12900, 410, ''),
    ('starter', 'Тахианы далавч BBQ', 'BBQ Chicken Wings',
     'Зөгийн бал, чинжүүтэй BBQ сүмсэнд булсан 8 ширхэг шүүслэг далавч. Селдерей, ранч сүмс дагалдана.',
     'Тахианы далавч, BBQ сүмс, зөгийн бал, чили', '8 ш · 350 гр', 16900, 520, 'spicy'),
    ('starter', 'Үхрийн хэлний зууш', 'Beef Tongue Platter',
     'Удаан жигнэж зөөллөсөн үхрийн хэл — гичийн сүмс, даршилсан өргөст хэмхтэй.',
     'Үхрийн хэл, гич, даршилсан ногоо', '150 гр', 14900, 320, ''),
    ('starter', 'Бяслагийн таваг', 'Cheese Board',
     'Гурван төрлийн бяслаг, наран хатаасан улаан лооль, самар, зөгийн балтай уулзвар таваг.',
     'Бяслаг, улаан лооль, хушга, зөгийн бал', '250 гр', 19900, 480, 'veg'),
    # ── САЛАТ ──
    ('salad', 'Цезарь салат тахиатай', 'Caesar Salad',
     'Ромэн шанцай, гриллд шарсан тахианы цээж, пармезан, шаргал крутонтой — өөрсдийн жорын цезарь сүмстэй.',
     'Ромэн, тахианы цээж, пармезан, крутон, цезарь сүмс', '320 гр', 14900, 380, 'special'),
    ('salad', 'Грек салат', 'Greek Salad',
     'Фета бяслаг, калмата олив, шинэ өргөст хэмх, улаан лооль — жинхэнэ газар дундын тэнгисийн амт.',
     'Фета, олив, өргөст хэмх, улаан лооль, улаан сонгино, орегано', '300 гр', 12900, 290, 'veg'),
    ('salad', 'Нийслэл салат', 'Niislel Salad',
     'Монголчуудын хайртай сонгодог — чанасан төмс, лууван, вандуй, утсан махтай, өтгөн майонезтой.',
     'Төмс, лууван, вандуй, чанасан мах, өндөг, майонез', '280 гр', 8900, 340, ''),
    ('salad', 'Капрезе', 'Caprese',
     'Үхрийн нүдэн улаан лооль, зөөлөн моцарелла, базилик — бальзамик багасгасан сүмсээр гоёсон.',
     'Улаан лооль, моцарелла, базилик, бальзамик', '250 гр', 13900, 310, 'veg'),
    ('salad', 'Туна загасны салат', 'Tuna Salad',
     'Туна, шинэ ногоон навч, өндөг, улаан буурцагтай тэжээллэг салат — лимоны сүмстэй.',
     'Туна, навчин салат, өндөг, улаан буурцаг, лимон', '300 гр', 15900, 350, ''),
    # ── ШӨЛ ──
    ('soup', 'Гуляш шөл', 'Goulash Soup',
     'Унгар маягийн паприкатай өтгөн шөл — зөөлөн болтол жигнэсэн үхрийн махтай.',
     'Үхрийн мах, паприка, төмс, улаан лооль', '400 мл', 11900, 380, ''),
    ('soup', 'Тахианы гоймонтой шөл', 'Chicken Noodle Soup',
     'Гэрийн жорын тунгалаг шөл — фермийн тахиа, гар гоймон, анхилуун ногоотой.',
     'Тахиа, гар гоймон, лууван, селдерей', '400 мл', 9900, 310, ''),
    ('soup', 'Банштай шөл', 'Dumpling Soup',
     'Нарийн мушгисан 12 банш бүхий үхрийн махан шөл — өвлийн хамгийн дулаан сонголт.',
     'Үхрийн мах, гурил, сонгино, ногоон сонгино', '450 мл', 8900, 350, ''),
    ('soup', 'Улаан лоолийн кремлэг шөл', 'Tomato Cream Soup',
     'Шарсан улаан лоолийн зөөлөн кремлэг шөл — базилик тос, гриссинитэй.',
     'Улаан лооль, цөцгий, базилик, сармис', '350 мл', 9900, 240, 'veg'),
    ('soup', 'Том Ям', 'Tom Yum',
     'Тайландын домогт халуун-исгэлэн шөл — том сам хорхой, галангал, лимон өвстэй.',
     'Сам хорхой, галангал, лимон өвс, чили, кокосын сүү', '400 мл', 16900, 300, 'spicy,new'),
    # ── ҮНДСЭН ХООЛ ──
    ('main', 'Тахианы шницель', 'Chicken Schnitzel',
     'Алтан шаргал үйрмэгэнд шарсан тахианы цээж — лимон, гарнирын сонголттой.',
     'Тахианы цээж, талх дурс, лимон', '280 гр', 16900, 620, ''),
    ('main', 'Үхрийн бифштекс', 'Beef Steak Patty',
     'Татсан үхрийн махан бифштекс — шарсан өндөг, карамель сонгинотой.',
     'Үхрийн татсан мах, өндөг, сонгино', '300 гр', 17900, 680, ''),
    ('main', 'Лосось стейк', 'Grilled Salmon',
     'Норвегийн лосось — цитрус тосон сүмс, гриль ногооны хамт. Омега-3-аар баялаг.',
     'Лосось, лимон, цөцгийн тос, ногоо', '220 гр', 32900, 450, 'special'),
    ('main', 'Гахайн карбонад', 'Pork Chop',
     'Ясан дээрээ шарсан гахайн сээр — алимны сүмс, розмаринтай.',
     'Гахайн сээр, алим, розмарин', '320 гр', 18900, 640, ''),
    ('main', 'Паста Карбонара', 'Pasta Carbonara',
     'Ром хотын сонгодог жор — гуанчиале, өндөгний шар, пекорино бяслагтай спагетти.',
     'Спагетти, гуанчиале, өндөг, пекорино', '350 гр', 15900, 720, ''),
    ('main', 'Паста Болоньезе', 'Pasta Bolognese',
     '4 цаг жигнэсэн махан рагу — аль денте спагетти, пармезантай.',
     'Спагетти, үхрийн татсан мах, улаан лооль, пармезан', '350 гр', 14900, 690, ''),
    ('main', 'Шампиньонтой ризотто', 'Mushroom Risotto',
     'Кремлэг арборио будаа — шарсан шампиньон, трюфелийн тос, пармезантай.',
     'Арборио будаа, шампиньон, трюфелийн тос, пармезан', '320 гр', 14900, 520, 'veg'),
    # ── ҮНДЭСНИЙ ХООЛ ──
    ('national', 'Хуушуур', 'Khuushuur',
     'Нимгэн элдсэн гурилд үхрийн махан чанамал хийж, алтан шаргал болтол шарсан — 4 ширхэг.',
     'Үхрийн мах, гурил, сонгино', '4 ш · 320 гр', 9900, 560, ''),
    ('national', 'Бууз', 'Buuz',
     'Өөхтэй хонины махыг гараар мушгиж жигнэсэн — 8 ширхэг, даршилсан ногоотой.',
     'Хонины мах, гурил, сонгино, сармис', '8 ш · 400 гр', 11900, 640, 'special'),
    ('national', 'Цуйван', 'Tsuivan',
     'Гар гоймонг махтай хуурч, шинэ ногоогоор баяжуулсан — монгол гэр бүлийн амт.',
     'Гурил, үхрийн мах, лууван, байцаа', '400 гр', 12900, 610, ''),
    ('national', 'Гурилтай шөл', 'Guriltai Shul',
     'Гар зүсмэл гурилтай махан шөл — өглөөний тэнхээ сэлбэх шилдэг сонголт.',
     'Үхрийн мах, гар гурил, төмс, лууван', '450 мл', 9900, 430, ''),
    ('national', 'Банштай цай', 'Bansh Tea',
     'Сүүтэй цайнд жижиг банш хийсэн үндэсний уламжлалт зоог.',
     'Сүү, цай, банш, давс', '400 мл', 4900, 210, ''),
    ('national', 'Хорхог', 'Khorkhog',
     'Халуун чулуугаар жигнэсэн хонины мах — 24 цагийн өмнө урьдчилан захиална. 2 хүний порц.',
     'Хонины мах, төмс, лууван, халуун чулуу', '2 хүн · 800 гр', 49900, 950, 'special'),
    # ── ГРИЛЬ & BBQ ──
    ('grill', 'Рибай стейк', 'Ribeye Steak',
     'Өөх нь жигд тархсан 300 гр рибай — 21 хоног чанар нэмэгдүүлсэн, чинарын модоор утсан.',
     'Үхрийн рибай, далайн давс, розмарин', '300 гр', 39900, 720, 'special'),
    ('grill', 'Т-Бон стейк', 'T-Bone Steak',
     'Хоёр бүтэцтэй домогт зүсэм — 400 гр, тендерлойн ба стриплойны уулзвар.',
     'Үхрийн T-bone, цөцгийн тос, сармис', '400 гр', 45900, 850, ''),
    ('grill', 'Хонины шорлог', 'Lamb Skewers',
     'Зүүн гарын жороор маринадалсан хонины мах — нүүрсэн дээр шарсан, сонгинотой.',
     'Хонины мах, сонгино, гоц амтлагч', '250 гр', 19900, 580, 'spicy'),
    ('grill', 'Тахианы шорлог', 'Chicken Skewers',
     'Тарагны маринадтай зөөлөн тахиа — гриль чинжүү, цацагт сүмстэй.',
     'Тахианы гуя, тараг, чинжүү', '250 гр', 16900, 490, ''),
    ('grill', 'BBQ хавирга', 'BBQ Pork Ribs',
     '6 цаг зөөлөн утсаны дараа BBQ сүмсээр паалантуулсан гахайн хавирга.',
     'Гахайн хавирга, BBQ сүмс, зөгийн бал', '500 гр', 29900, 880, ''),
    ('grill', 'Гриль хольц', 'Mixed Grill Platter',
     'Рибай, тахиа, хонины шорлог, шарсан ногоо — найзуудтайгаа хуваалцах том таваг. 2-3 хүний порц.',
     'Үхэр, тахиа, хонь, ногоо', '2-3 хүн · 900 гр', 59900, 1400, 'special'),
    # ── ГАРНИР ──
    ('side', 'Шарсан төмс', 'French Fries',
     'Гадуураа шаржигнасан, дотроо зөөлөн — далайн давс, розмаринтай.',
     'Төмс, ургамлын тос, далайн давс', '200 гр', 4900, 340, 'veg'),
    ('side', 'Төмсний нухаш', 'Mashed Potato',
     'Цөцгийн тос, бүлээн сүүгээр нухсан торгомсог нухаш.',
     'Төмс, цөцгийн тос, сүү', '200 гр', 4500, 280, 'veg'),
    ('side', 'Гриль ногоо', 'Grilled Vegetables',
     'Цуккини, чинжүү, хаш — оливын тос, бальзамикаар амталсан.',
     'Цуккини, чинжүү, хаш, оливын тос', '180 гр', 6900, 150, 'veg'),
    ('side', 'Цагаан будаа', 'Steamed Rice',
     'Жасмин будаа — уураар жигнэсэн, сэвсгэр.',
     'Жасмин будаа', '180 гр', 3500, 260, 'veg'),
    # ── АМТТАН ──
    ('dessert', 'Тирамису', 'Tiramisu',
     'Эспрессонд дэвтээсэн савоярди, маскарпоне кремтэй — гэрийн жорын итали сонгодог.',
     'Маскарпоне, савоярди, эспрессо, какао', '150 гр', 10900, 420, 'special'),
    ('dessert', 'Шоколадтай фондан', 'Chocolate Fondant',
     'Халуун зүсэхэд урсдаг 70% хар шоколадтай бялуу — ванилийн зайрмагтай.',
     'Хар шоколад, өндөг, цөцгийн тос, зайрмаг', '180 гр', 12900, 510, 'new'),
    ('dessert', 'Нью-Йорк чизкейк', 'NY Cheesecake',
     'Өтгөн кремлэг cream cheese, шаржигнуур суурьтай — жимсний сүмсээр.',
     'Cream cheese, цөцгий, жигнэмэг, жимс', '160 гр', 10900, 460, ''),
    ('dessert', 'Зайрмагны таваг', 'Ice Cream Selection',
     'Ваниль, шоколад, гүзээлзгэнэ — 3 бөмбөлөг, самар, жимсээр гоёно.',
     'Зайрмаг, самар, жимс', '3 бөмбөлөг', 6900, 300, ''),
    ('dessert', 'Улирлын жимсний таваг', 'Seasonal Fruit Platter',
     'Өдөр бүр шинээр бэлтгэдэг улирлын шилмэл жимс.',
     'Улирлын жимс', '350 гр', 12900, 180, 'veg'),
    # ── УНДАА ──
    ('drink', 'Шинэ шахсан жүржийн шүүс', 'Fresh Orange Juice',
     'Захиалга бүрд шинээр шахна — 100% жүрж, нэмэлтгүй.',
     'Жүрж', '300 мл', 8900, 160, 'veg'),
    ('drink', 'Гэрийн лимонад', 'House Lemonade',
     'Лимон, гаа, бага зэрэг зөгийн балтай — өөрсдийн жор.',
     'Лимон, гаа, зөгийн бал, содтой ус', '400 мл', 6900, 140, 'new,veg'),
    ('drink', 'Рашаан ус', 'Mineral Water',
     'Хийтэй эсвэл хийгүй сонголттой.',
     'Байгалийн рашаан', '500 мл', 2900, 0, 'veg'),
    ('drink', 'Ундаа', 'Soft Drinks',
     'Кока-Кола, Спрайт, Фанта — мөстэй, лимонтой.',
     '', '330 мл', 3900, 140, ''),
    # ── КОФЕ & ЦАЙ ──
    ('hotdrink', 'Эспрессо', 'Espresso',
     '100% арабика — дунд хуурсан, шоколадлаг амттай.',
     'Арабика кофе', '30 мл', 4900, 5, 'veg'),
    ('hotdrink', 'Капучино', 'Cappuccino',
     'Эспрессо, уурын сүү, зузаан хөөс — сонгодог харьцаагаар.',
     'Эспрессо, сүү', '200 мл', 6900, 120, 'veg'),
    ('hotdrink', 'Латте', 'Caffè Latte',
     'Зөөлөн сүүлэг кофе — латте арт-тай.',
     'Эспрессо, сүү', '300 мл', 7400, 180, 'veg'),
    ('hotdrink', 'Жимсний цай', 'Berry Tea Pot',
     'Чацаргана, нэрс, бөөрөлзгөнөтэй халуун цай — данхаар, 2-3 аяга.',
     'Чацаргана, нэрс, бөөрөлзгөнө, зөгийн бал', '600 мл', 8900, 90, 'veg'),
]


# ── DATABASE ────────────────────────────────────────────
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS dishes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        name_en TEXT,
        category TEXT DEFAULT 'main',
        description TEXT,
        ingredients TEXT,
        portion TEXT,
        price REAL,
        kcal INTEGER,
        photo TEXT,
        tags TEXT,
        is_active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 99,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    if not conn.execute("SELECT COUNT(*) c FROM dishes").fetchone()['c']:
        for i, (cat, name, en, desc, ingr, portion, price, kcal, tags) in enumerate(SEED_DISHES):
            conn.execute("""INSERT INTO dishes
                (name, name_en, category, description, ingredients, portion, price, kcal, tags, sort_order)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (name, en, cat, desc, ingr or None, portion or None,
                 price, kcal or None, tags or None, i))
        print(f'✓ Меню бэлэн — {len(SEED_DISHES)} хоол')
    conn.commit()
    conn.close()

def dish_dict(d):
    return {
        'id': d['id'], 'name': d['name'], 'name_en': d['name_en'],
        'category': d['category'], 'desc': d['description'],
        'ingredients': d['ingredients'], 'portion': d['portion'],
        'price': d['price'], 'kcal': d['kcal'], 'photo': d['photo'],
        'tags': d['tags'].split(',') if d['tags'] else [],
        'active': d['is_active'], 'sort': d['sort_order'],
    }

def save_photo(file):
    if not file or not file.filename:
        return None
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('jpg', 'jpeg', 'png', 'webp'):
        return None
    name = f"{uuid.uuid4().hex}.{ext}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    dest = os.path.join(UPLOAD_DIR, name)
    try:
        from PIL import Image
        img = Image.open(file.stream)
        img.thumbnail((1200, 1200), Image.LANCZOS)
        img.save(dest, 'JPEG' if ext in ('jpg', 'jpeg') else ext.upper(),
                 quality=90, optimize=True)
    except Exception:
        file.stream.seek(0)
        file.save(dest)
    return name


# ── PUBLIC MENU ─────────────────────────────────────────
@app.route('/')
def menu():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM dishes WHERE is_active=1 ORDER BY sort_order, id").fetchall()
    conn.close()
    dishes = [dish_dict(d) for d in rows]
    return render_template('menu.html', dishes=dishes, cats=CATEGORIES,
                           tag_defs=TAGS, r=RESTAURANT,
                           is_admin=session.get('admin', False))


# ── ADMIN ───────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin'))
        flash('Нууц үг буруу байна.', 'error')
    return render_template('login.html', r=RESTAURANT)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('menu'))

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def dec(*a, **kw):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec

@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    rows = conn.execute("SELECT * FROM dishes ORDER BY sort_order, id").fetchall()
    conn.close()
    return render_template('admin.html', dishes=[dish_dict(d) for d in rows],
                           cats=CATEGORIES, tag_defs=TAGS, r=RESTAURANT)

def _form_values():
    tags = ','.join(request.form.getlist('tags')) or None
    try:
        sort_order = int(request.form.get('sort_order') or 99)
    except ValueError:
        sort_order = 99
    return (
        request.form.get('name', '').strip(),
        request.form.get('name_en', '').strip() or None,
        request.form.get('category', 'main'),
        request.form.get('description', '').strip() or None,
        request.form.get('ingredients', '').strip() or None,
        request.form.get('portion', '').strip() or None,
        request.form.get('price') or None,
        request.form.get('kcal') or None,
        tags, sort_order,
    )

@app.route('/admin/dish/add', methods=['POST'])
@admin_required
def dish_add():
    vals = _form_values()
    if not vals[0]:
        flash('Хоолны нэр оруулна уу.', 'error')
        return redirect(url_for('admin'))
    photo = save_photo(request.files.get('photo'))
    conn = get_db()
    conn.execute("""INSERT INTO dishes
        (name, name_en, category, description, ingredients, portion, price, kcal, tags, sort_order, photo)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)""", vals + (photo,))
    conn.commit(); conn.close()
    flash(f'«{vals[0]}» менюнд нэмэгдлээ.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/dish/<int:did>/edit', methods=['POST'])
@admin_required
def dish_edit(did):
    conn = get_db()
    dish = conn.execute("SELECT * FROM dishes WHERE id=?", (did,)).fetchone()
    if not dish:
        conn.close()
        flash('Хоол олдсонгүй.', 'error')
        return redirect(url_for('admin'))
    vals = _form_values()
    if not vals[0]:
        vals = (dish['name'],) + vals[1:]
    photo = save_photo(request.files.get('photo')) or dish['photo']
    conn.execute("""UPDATE dishes SET
        name=?, name_en=?, category=?, description=?, ingredients=?, portion=?,
        price=?, kcal=?, tags=?, sort_order=?, photo=? WHERE id=?""",
        vals + (photo, did))
    conn.commit(); conn.close()
    flash(f'«{vals[0]}» шинэчлэгдлээ.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/dish/<int:did>/toggle', methods=['POST'])
@admin_required
def dish_toggle(did):
    conn = get_db()
    conn.execute("UPDATE dishes SET is_active = 1 - is_active WHERE id=?", (did,))
    conn.commit(); conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/dish/<int:did>/delete', methods=['POST'])
@admin_required
def dish_delete(did):
    conn = get_db()
    conn.execute("DELETE FROM dishes WHERE id=?", (did,))
    conn.commit(); conn.close()
    flash('Хоол менюнээс устгагдлаа.', 'success')
    return redirect(url_for('admin'))


init_db()

if __name__ == '__main__':
    print('🍽  Хүрэншанд ресторан — меню апп')
    print('Меню:  http://localhost:5001')
    print('Админ: http://localhost:5001/admin  (нууц үг: resto123)')
    app.run(debug=False, host='0.0.0.0', port=5001)
