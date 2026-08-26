"""Run Alembic migrations programmatically.

Usage:
  python3 backend/scripts/run_alembic.py

This attempts to import Alembic and run `upgrade head`. If Alembic is not
installed, it prints instructions to install and falls back to the app's
`init_db()` helper.
"""
import os
import sys
from subprocess import CalledProcessError, run

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, ROOT)


def main():
    try:
        import alembic.config as alembic_config
        from alembic import command
        cfg_path = os.path.join(ROOT, 'backend', 'alembic.ini')
        if not os.path.exists(cfg_path):
            print('alembic.ini not found; falling back to init_db()')
            raise ImportError
        print('Running Alembic: upgrade head')
        command.upgrade(alembic_config.Config(cfg_path), 'head')
        print('Alembic upgrade completed')
        return
    except Exception:
        print('Alembic not available or failed. Falling back to init_db()')
        try:
            # call the fallback apply script
            run(['python3', os.path.join('backend', 'scripts', 'apply_migrations.py')], check=True)
        except CalledProcessError as exc:
            print('Fallback migration failed:', exc)


if __name__ == '__main__':
    main()
