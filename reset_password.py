import sqlite3, os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'lab.db')

def reset():
    print("=" * 40)
    print("  Nuuts ug shinechleh")
    print("=" * 40)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    users = conn.execute(
        "SELECT id, employee_id, name, role FROM users WHERE is_active=1 ORDER BY role, name"
    ).fetchall()

    print("\nAjiltanuudiin jagsaalt:")
    print("-" * 40)
    for u in users:
        if u['role'] == 'admin':
            role_lbl = "Admin"
        elif u['role'] == 'senior':
            role_lbl = "Ahlah himich"
        else:
            role_lbl = "Ajiltan"
        print(f"  {u['employee_id']:12} | {u['name']:20} | {role_lbl}")
    print("-" * 40)

    emp_id = input("\nAjiltanii ID oruulna uu (jiishee: ADMIN): ").strip()
    user = conn.execute("SELECT * FROM users WHERE employee_id=?", (emp_id,)).fetchone()

    if not user:
        print(f"\n OLDSONGUII: '{emp_id}'")
        conn.close()
        return

    print(f"\nOldsloo: {user['name']} ({user['role']})")
    new_pw = input("Shine nuuts ug (6+ temdeget): ").strip()

    if len(new_pw) < 6:
        print("\nNuuts ug het bogino!")
        conn.close()
        return

    confirm = input("Dahin oruulna uu: ").strip()
    if new_pw != confirm:
        print("\nNuuts ug taarahuui!")
        conn.close()
        return

    conn.execute("UPDATE users SET password_hash=? WHERE employee_id=?",
                (generate_password_hash(new_pw), emp_id))
    conn.commit()
    conn.close()

    print(f"\nAmjilttai! {user['name']}-n nuuts ug shinechilegdlee!")
    print(f"Shine nuuts ug: {new_pw}")

if __name__ == '__main__':
    reset()
    input("\nEnter darj haana uu...")
