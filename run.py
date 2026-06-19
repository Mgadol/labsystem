"""
Production server — app.py-ийн оронд энийг ашиглана.
  python run.py
"""
from app import app
from models import get_db, init_db
from models import init_analysis_db

if __name__ == '__main__':
    init_db()
    init_analysis_db()
    from app import ensure_tables
    ensure_tables()

    print('=' * 50)
    print('  Лабораторийн систем эхэллээ (Production)')
    print('  Локал:    http://localhost:5000')
    print('  Сүлжээ:   http://0.0.0.0:5000')
    print('  Зогсоох:  Ctrl+C')
    print('=' * 50)

    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000, threads=4,
              channel_timeout=120, cleanup_interval=30)
    except ImportError:
        print('⚠️  waitress суугаагүй. pip install waitress')
        print('   Flask dev server ашиглаж байна...')
        app.run(debug=False, host='0.0.0.0', port=5000)
