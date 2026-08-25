"""Apply initial DB schema using the application's init_db().

This is a safe fallback for environments where Alembic isn't installed.
Run from the repository root:

python3 backend/scripts/apply_migrations.py
"""
import os
import sys

# Ensure repository workspace root is on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, ROOT)

try:
    # try package import
    from backend.main import init_db
except Exception:
    # fallback to direct import by path
    import importlib.util
    MAIN_PATH = os.path.join(ROOT, 'backend', 'main.py')
    spec = importlib.util.spec_from_file_location('backend_main', MAIN_PATH)
    backend_main = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend_main)
    init_db = backend_main.init_db


def main():
    print('Applying initial DB schema (init_db)...')
    init_db()
    print('Done')


if __name__ == '__main__':
    main()
