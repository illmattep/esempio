import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.main import create_user, get_user, init_db


def main() -> None:
    init_db()
    username = input("Username: ").strip()
    if not username:
        raise SystemExit("Username richiesto")
    if get_user(username):
        raise SystemExit("Utente gia esistente")
    password = getpass.getpass("Password: ")
    if not password:
        raise SystemExit("Password richiesta")
    create_user(username, password)
    print("Utente creato")


if __name__ == "__main__":
    main()
