from logging.config import fileConfig
import os
import sys

from sqlalchemy import engine_from_config, pool, create_engine
from alembic import context
from dotenv import load_dotenv

# Ensure backend root is on sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Load .env without overriding any existing environment variables
load_dotenv(override=False)

# Import Base from db.database as required
from db.database import Base
import db.models  # Register all models with Base.metadata

# Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Set target metadata for 'autogenerate' support
target_metadata = Base.metadata

# Read DATABASE_URL from config (if programmatically overridden for tests) or os.environ without overwriting production credentials
explicit_url = config.get_main_option("sqlalchemy.url")
if explicit_url and not explicit_url.startswith("driver://"):
    database_url = explicit_url
else:
    database_url = os.environ.get("DATABASE_URL")

if not database_url:
    env = os.environ.get("ENVIRONMENT", os.environ.get("ENV", "development")).strip().lower()
    if env in ("production", "prod"):
        raise RuntimeError("DATABASE_URL environment variable is required in production and cannot be empty.")
    database_url = "sqlite:///./finfamily.db"

# Normalizing postgresql schema identifier if needed (e.g., postgres:// -> postgresql://)
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Escape percent signs for configparser
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well. By skipping the Engine creation
    we don't even need a DBAPI to be available.
    """
    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connection = config.attributes.get("connection", None)
    if connection is not None:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    is_sqlite = database_url.startswith("sqlite")
    connect_args = {}
    if is_sqlite:
        connect_args["check_same_thread"] = False

    connectable = create_engine(
        database_url,
        connect_args=connect_args,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
