# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import unittest
import pytest
from flask_appbuilder.security.sqla.models import Role
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

        # Create User with access to only Dataset 1 using a custom role
        self.user = security_manager.find_user("test_user")
        if not self.user:
            self.user = self.create_user(
                "test_user", "password", "Public", email="test_user@superset.org"
            )

        # Create a custom role
        role_name = "TestSecurityRole"
        self.role = security_manager.find_role(role_name)
        if not self.role:
            self.role = security_manager.add_role(role_name)

        # Add basic permissions to the role
        # We need "can read on Dashboard", "can read on Chart"
        read_dash = security_manager.find_permission_view_menu("can_read", "Dashboard")
        read_chart = security_manager.find_permission_view_menu("can_read", "Chart")
        if read_dash and read_dash not in self.role.permissions:
             self.role.permissions.append(read_dash)
        if read_chart and read_chart not in self.role.permissions:
             self.role.permissions.append(read_chart)

        # Add permission to dataset1
        perm_view = security_manager.add_permission_view_menu(
            "datasource_access", self.dataset1.perm
        )
        if perm_view not in self.role.permissions:
            self.role.permissions.append(perm_view)

        self.user.roles = [self.role]
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
        if self.role:
            db.session.delete(self.role)

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
