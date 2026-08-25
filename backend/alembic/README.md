Alembic migration helper

This folder contains a minimal Alembic scaffold. To use Alembic for real migrations:

1. Install Alembic in your backend venv:

   pip install alembic

2. Initialize Alembic (if not already):

   alembic init alembic

3. Edit `alembic.ini` to set `sqlalchemy.url = <your DATABASE_URL>` or export `DATABASE_URL`.

4. Create a revision with autogenerate or a manual SQL script. Example:

   alembic revision -m "create initial tables" --autogenerate

5. Apply migrations:

   alembic upgrade head

This repo's `init_db()` still provides a safe migration path for small setups, but for production use Alembic is recommended.
