import argparse,sqlite3,os
from pathlib import Path
p=argparse.ArgumentParser(description="Excluir dados de um titular da academia")
p.add_argument("--delete-email",required=True)
a=p.parse_args()
path=Path(os.environ.get("DATA_DIR",str(Path(__file__).parent/"instance")))/"academy.sqlite3"
if not path.exists():raise SystemExit("Banco ainda não criado.")
with sqlite3.connect(path) as db:
 row=db.execute("SELECT id FROM users WHERE email=?",(a.delete_email.strip().lower(),)).fetchone()
 if row:
  db.execute("DELETE FROM tokens WHERE user_id=?",(row[0],));db.execute("DELETE FROM users WHERE id=?",(row[0],))
 print("Solicitação processada. Registros associados removidos quando existentes.")
