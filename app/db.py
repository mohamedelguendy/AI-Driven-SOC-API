from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

# Rows come back as dicts, e.g. user["role"]
pool = ConnectionPool(
    settings.database_url,
    kwargs={"row_factory": dict_row},
    open=True,
)