import unittest
import pytest
from superset import db, security_manager
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice
from superset.connectors.sqla.models import SqlaTable
from superset.utils.core import get_example_database
from tests.integration_tests.base_tests import SupersetTestCase

class TestDashboardChartsSecurity(SupersetTestCase):
    def setUp(self):
        super().setUp()
        self.login("admin")

        # Ensure roles exist
        security_manager.sync_role_definitions()

        # Create 2 datasets
        self.db = get_example_database()

        # Check if tables exist and delete them if they do
        self.dataset1 = db.session.query(SqlaTable).filter_by(table_name="test_table_1").one_or_none()
        if self.dataset1:
            db.session.delete(self.dataset1)
        self.dataset2 = db.session.query(SqlaTable).filter_by(table_name="test_table_2").one_or_none()
        if self.dataset2:
            db.session.delete(self.dataset2)
        db.session.commit()

        self.dataset1 = SqlaTable(
            table_name="test_table_1",
            database=self.db,
            schema="public"
        )
        self.dataset2 = SqlaTable(
            table_name="test_table_2",
            database=self.db,
            schema="public"
        )
        db.session.add(self.dataset1)
        db.session.add(self.dataset2)
        db.session.commit()

        # Refresh to ensure perms are generated
        self.dataset1 = db.session.query(SqlaTable).get(self.dataset1.id)
        self.dataset2 = db.session.query(SqlaTable).get(self.dataset2.id)

        # Create 2 charts
        self.chart1 = Slice(
            slice_name="Chart 1",
            datasource_type="table",
            datasource_id=self.dataset1.id,
            viz_type="table",
            params="{}"
        )
        self.chart2 = Slice(
            slice_name="Chart 2",
            datasource_type="table",
            datasource_id=self.dataset2.id,
            viz_type="table",
            params="{}"
        )
        db.session.add(self.chart1)
        db.session.add(self.chart2)
        db.session.commit()

        # Create Dashboard
        self.dashboard = Dashboard(
            dashboard_title="Security Test Dashboard",
            slug="security-test-dashboard",
            slices=[self.chart1, self.chart2],
            published=True
        )
        db.session.add(self.dashboard)
        db.session.commit()

        # Create User with access to only Dataset 1
        # Check if user exists
        self.user = security_manager.find_user("test_user")
        if not self.user:
            self.user = self.create_user(
                "test_user", "password", "Gamma", email="test_user@superset.org"
            )

        # Grant access to Dataset 1
        gamma_role = security_manager.find_role("Gamma")
        if not gamma_role:
             # Create Gamma role if it doesn't exist (though sync_role_definitions should have created it)
             gamma_role = security_manager.add_role("Gamma")

        perm_view = security_manager.add_permission_view_menu(
            "datasource_access", self.dataset1.perm
        )
        if perm_view not in gamma_role.permissions:
            gamma_role.permissions.append(perm_view)
        db.session.commit()

    def tearDown(self):
        self.login("admin")
        db.session.delete(self.dashboard)
        db.session.delete(self.chart1)
        db.session.delete(self.chart2)
        db.session.delete(self.dataset1)
        db.session.delete(self.dataset2)
        if self.user:
            db.session.delete(self.user)

        gamma_role = security_manager.find_role("Gamma")
        if hasattr(self, 'dataset1') and self.dataset1:
             perm_view = security_manager.find_permission_view_menu(
                "datasource_access", self.dataset1.perm
             )
             if perm_view and perm_view in gamma_role.permissions:
                 gamma_role.permissions.remove(perm_view)

        db.session.commit()
        super().tearDown()

    def test_get_charts_vulnerability(self):
        self.login("test_user", "password")

        uri = f"api/v1/dashboard/{self.dashboard.id}/charts"
        rv = self.client.get(uri)
        assert rv.status_code == 200

        data = rv.json["result"]
        chart_ids = [c["id"] for c in data]

        assert self.chart1.id in chart_ids
        # The user should NOT have access to chart 2 (dataset 2)
        assert self.chart2.id not in chart_ids

    def test_get_datasets_vulnerability(self):
        self.login("test_user", "password")

        uri = f"api/v1/dashboard/{self.dashboard.id}/datasets"
        rv = self.client.get(uri)
        assert rv.status_code == 200

        data = rv.json["result"]
        dataset_ids = [d["id"] for d in data]

        assert self.dataset1.id in dataset_ids
        # The user should NOT have access to dataset 2
        assert self.dataset2.id not in dataset_ids
