import pytest

from tests.integration_tests.base_tests import SupersetTestCase


class TestSqlLabSecurity(SupersetTestCase):
    def test_stop_query_idor(self):
        from superset import db
        from superset.daos.query import QueryDAO
        from superset.exceptions import QueryNotFoundException
        from superset.models.sql_lab import Query
        from tests.integration_tests.constants import (
            ADMIN_USERNAME,
            GAMMA_SQLLAB_NO_DATA_USERNAME,
        )

        self.login(ADMIN_USERNAME)
        admin_user = self.get_user(ADMIN_USERNAME)

        # Create a query for admin
        query = Query(client_id="admin_query", user_id=admin_user.id, database_id=1)
        db.session.add(query)
        db.session.commit()

        # Now login as Gamma
        self.logout()
        self.login(GAMMA_SQLLAB_NO_DATA_USERNAME)
        gamma_user = self.get_user(GAMMA_SQLLAB_NO_DATA_USERNAME)
        assert gamma_user.id != admin_user.id

        # Gamma tries to stop admin's query via DAO
        with pytest.raises(QueryNotFoundException):
            QueryDAO.stop_query("admin_query")

        # Cleanup
        self.logout()
        self.login(ADMIN_USERNAME)
        db.session.delete(query)
        db.session.commit()
