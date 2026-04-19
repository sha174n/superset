import pytest

from tests.integration_tests.base_tests import SupersetTestCase


class TestSqlLabSecurity(SupersetTestCase):
    def test_stop_query_idor(self):
        import uuid

        from superset import db
        from superset.daos.query import QueryDAO
        from superset.exceptions import QueryNotFoundException
        from superset.models.sql_lab import Query
        from tests.integration_tests.constants import (
            ADMIN_USERNAME,
            GAMMA_SQLLAB_NO_DATA_USERNAME,
        )

        client_id = f"admin_query_{uuid.uuid4().hex[:8]}"
        self.login(ADMIN_USERNAME)
        admin_user = self.get_user(ADMIN_USERNAME)

        # Create a query for admin
        query = Query(client_id=client_id, user_id=admin_user.id, database_id=1)
        db.session.add(query)
        db.session.commit()

        # Now login as Gamma
        self.logout()
        self.login(GAMMA_SQLLAB_NO_DATA_USERNAME)
        gamma_user = self.get_user(GAMMA_SQLLAB_NO_DATA_USERNAME)
        assert gamma_user.id != admin_user.id

        # Gamma tries to stop admin's query via DAO
        with pytest.raises(QueryNotFoundException):
            QueryDAO.stop_query(client_id)

        # Cleanup
        self.logout()
        self.login(ADMIN_USERNAME)
        db.session.delete(query)
        db.session.commit()

    def test_jinja_context_security(self):
        from unittest import mock

        from sqlalchemy.dialects import sqlite

        from superset.jinja_context import ExtraCache

        cache = ExtraCache(dialect=sqlite.dialect())

        # Test url_param escaping from request.args
        with self.app.test_request_context("/?foo=bar'OR'1'='1"):
            val = cache.url_param("foo")
            assert val == "bar''OR''1''=''1"

        # Test get_filters escaping
        with mock.patch("superset.views.utils.get_form_data") as mock_get_form_data:
            mock_get_form_data.return_value = (
                {
                    "adhoc_filters": [
                        {
                            "expressionType": "SIMPLE",
                            "clause": "WHERE",
                            "subject": "col1",
                            "operator": "==",
                            "comparator": "val'OR'1'='1",
                        }
                    ]
                },
                None,
            )

            filters = cache.get_filters("col1")
            assert filters[0]["val"] == "val''OR''1''=''1"

        # Test filter_values escaping
        with mock.patch("superset.views.utils.get_form_data") as mock_get_form_data:
            mock_get_form_data.return_value = (
                {
                    "adhoc_filters": [
                        {
                            "expressionType": "SIMPLE",
                            "clause": "WHERE",
                            "subject": "col1",
                            "operator": "IN",
                            "comparator": ["val1'", "val2"],
                        }
                    ]
                },
                None,
            )

            values = cache.filter_values("col1")
            assert values == ["val1''", "val2"]

    def test_postgres_schema_sqli(self):
        from unittest import mock

        from superset.db_engine_specs.postgres import PostgresEngineSpec

        database = mock.MagicMock()
        mock_dialect = mock.MagicMock()
        database.get_dialect.return_value = mock_dialect
        # Simulate Postgres double-quote escaping
        mock_dialect.identifier_preparer.quote.side_effect = lambda x: (
            '"' + x.replace('"', '""') + '"'
        )

        evil_schema = 'public"; DROP TABLE users; --'
        prequeries = PostgresEngineSpec.get_prequeries(database, schema=evil_schema)

        assert len(prequeries) == 1
        assert prequeries[0] == 'set search_path = "public""; DROP TABLE users; --"'
