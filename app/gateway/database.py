"""Typed obligations and fixed, parameterized protected-data queries."""

from typing import Literal

from pydantic import Field, model_validator
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.models import StrictModel, Department

TABLES = {
    "customers": "customer_data",
    "financial": "financial_records",
    "production": "production_logs",
}
COLUMNS = {
    "customers": {"id", "department", "name", "email", "salary", "national_id"},
    "financial": {"id", "department", "period", "revenue"},
    "production": {"id", "department", "event", "severity"},
}


class RowScope(StrictModel):
    kind: Literal["all", "department"]
    value: Department | None = None

    @model_validator(mode="after")
    def valid_scope(self):
        if (self.kind == "department") != (self.value is not None):
            raise ValueError("Invalid row scope")
        return self


class ViewPlan(StrictModel):
    version: Literal[1]
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    policy_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    resource: Literal["customers", "financial", "production"]
    columns: list[str] = Field(min_length=1)
    mask: list[str]
    row_scope: RowScope
    limit: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def valid_columns(self):
        if (
            len(set(self.columns)) != len(self.columns)
            or not set(self.columns) <= COLUMNS[self.resource]
        ):
            raise ValueError("Unsupported columns")
        if len(set(self.mask)) != len(self.mask) or not set(self.mask) <= set(self.columns):
            raise ValueError("Unsupported mask")
        if not set(self.mask) <= {"email", "salary", "national_id"}:
            raise ValueError("Unknown masking operation")
        return self


class Database:
    def __init__(self, url):
        self.pool = ConnectionPool(
            url,
            min_size=0,
            max_size=5,
            open=True,
            timeout=5,
            kwargs={"row_factory": dict_row, "connect_timeout": 3},
        )

    def query(self, plan):
        # Mask in SELECT, so raw protected fields never reach Python or response logs.
        fields = []
        for column in plan.columns:
            if column in plan.mask:
                fields.append(sql.SQL("'REDACTED'::text AS {} ").format(sql.Identifier(column)))
            else:
                fields.append(sql.Identifier(column))
        query = sql.SQL(
            "SELECT {} FROM {} WHERE tenant_id = %s AND {} ORDER BY id LIMIT %s"
        ).format(
            sql.SQL(", ").join(fields),
            sql.Identifier(TABLES[plan.resource]),
            sql.SQL("department = %s") if plan.row_scope.kind == "department" else sql.SQL("TRUE"),
        )
        params = (
            [plan.tenant_id]
            + ([plan.row_scope.value] if plan.row_scope.kind == "department" else [])
            + [plan.limit]
        )
        with self.pool.connection() as connection:
            connection.execute("SET LOCAL statement_timeout = '3s'")
            connection.execute(
                "SELECT set_config('gateway.scope', %s, true), set_config('gateway.department', %s, true), "
                "set_config('gateway.tenant_id', %s, true)",
                (plan.row_scope.kind, plan.row_scope.value or "", plan.tenant_id),
            )
            return connection.execute(query, params).fetchall()

    def close(self):
        self.pool.close()

    def ready(self):
        with self.pool.connection() as connection:
            return connection.execute("SELECT 1").fetchone()["?column?"] == 1
