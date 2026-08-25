"""
Minimal Alembic env.py scaffold for manual migrations.
This file is intentionally small — run Alembic from the backend directory:

pip install alembic
alembic init alembic

Replace this file with a generated one when you run `alembic init`.
"""
from logging.config import fileConfig
from alembic import context
import os

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Interpret the config file for Python logging.
# Add your model's MetaData object here for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata

target_metadata = None

def run_migrations_offline():
    context.configure(url=os.getenv('DATABASE_URL'))
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = None
    context.configure(connection=connectable, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
