import pytest
from marshmallow import ValidationError

from superset.sqllab.schemas import ExecutePayloadSchema
from tests.integration_tests.base_tests import SupersetTestCase


class TestSqlLimit(SupersetTestCase):
    def test_sql_limit(self):
        self.app.config["SQLLAB_MAX_SQL_LENGTH"] = 100
        schema = ExecutePayloadSchema()

        # Should pass
        schema.load({"database_id": 1, "sql": "SELECT 1"})

        # Should fail
        with pytest.raises(ValidationError) as excinfo:
            schema.load({"database_id": 1, "sql": "SELECT " + "a" * 100})
        assert "too long" in str(excinfo.value)

    def test_sql_limit_format(self):
        from superset.sqllab.schemas import FormatQueryPayloadSchema

        self.app.config["SQLLAB_MAX_SQL_LENGTH"] = 100
        schema = FormatQueryPayloadSchema()

        # Should pass
        schema.load({"sql": "SELECT 1"})

        # Should fail
        with pytest.raises(ValidationError) as excinfo:
            schema.load({"sql": "SELECT " + "a" * 100})
        assert "too long" in str(excinfo.value)
