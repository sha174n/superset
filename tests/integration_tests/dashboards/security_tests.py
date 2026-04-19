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
import uuid
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

        # Use unique suffix to prevent collisions
        self.uid = uuid.uuid4().hex[:8]
        self.role_name = f"TestSecurityRole_{self.uid}"
        self.username = f"test_user_{self.uid}"

        # Ensure roles exist
        security_manager.sync_role_definitions()

        self.db = get_example_database()

        # Create 2 datasets
        self.dataset1 = SqlaTable(
            table_name=f"test_table_1_{self.uid}",
            database=self.db,
            schema="public"
        )
        self.dataset2 = SqlaTable(
            table_name=f"test_table_2_{self.uid}",
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
            slice_name=f"Chart 1 {self.uid}",
            datasource_type="table",
            datasource_id=self.dataset1.id,
            viz_type="table",
            params="{}"
        )
        self.chart2 = Slice(
            slice_name=f"Chart 2 {self.uid}",
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
            dashboard_title=f"Security Test Dashboard {self.uid}",
            slug=f"security-test-dashboard-{self.uid}",
            slices=[self.chart1, self.chart2],
            published=True
        )
        db.session.add(self.dashboard)
        db.session.commit()

        # Create User
        self.user = self.create_user(
            self.username, "password", "Public", email=f"{self.username}@superset.org"
        )

        # Create a custom role
        self.role = security_manager.add_role(self.role_name)

        # Add basic permissions to the role
        # We need "can read on Dashboard", "can read on Chart"
        read_dash = security_manager.find_permission_view_menu("can_read", "Dashboard")
        read_chart = security_manager.find_permission_view_menu("can_read", "Chart")
        if read_dash:
             self.role.permissions.append(read_dash)
        if read_chart:
             self.role.permissions.append(read_chart)

        # Add permission to dataset1 ONLY
        perm_view = security_manager.add_permission_view_menu(
            "datasource_access", self.dataset1.perm
        )
        self.role.permissions.append(perm_view)

        # Assign ONLY this role to the user (remove Public)
        self.user.roles = [self.role]
        db.session.commit()

    def tearDown(self):
        self.login("admin")

        # Re-fetch objects to ensure they are attached to the session before deletion
        dashboard = db.session.query(Dashboard).filter_by(id=self.dashboard.id).first()
        if dashboard:
            db.session.delete(dashboard)

        chart1 = db.session.query(Slice).filter_by(id=self.chart1.id).first()
        if chart1:
            db.session.delete(chart1)

        chart2 = db.session.query(Slice).filter_by(id=self.chart2.id).first()
        if chart2:
            db.session.delete(chart2)

        dataset1 = db.session.query(SqlaTable).filter_by(id=self.dataset1.id).first()
        if dataset1:
            db.session.delete(dataset1)

        dataset2 = db.session.query(SqlaTable).filter_by(id=self.dataset2.id).first()
        if dataset2:
            db.session.delete(dataset2)

        user = security_manager.find_user(self.username)
        if user:
            db.session.delete(user)

        role = security_manager.find_role(self.role_name)
        if role:
            db.session.delete(role)

        db.session.commit()
        super().tearDown()

    def test_get_charts_vulnerability(self):
        self.login(self.username, "password")

        # Re-fetch dashboard ID to ensure session consistency
        dashboard = db.session.query(Dashboard).filter_by(id=self.dashboard.id).one()

        uri = f"api/v1/dashboard/{dashboard.id}/charts"
        rv = self.client.get(uri)
        assert rv.status_code == 200, f"Request failed with {rv.status}"

        data = rv.json["result"]
        chart_ids = [c["id"] for c in data]

        # Re-fetch chart IDs to avoid DetachedInstanceError
        chart1_id = self.chart1.id
        chart2_id = self.chart2.id

        assert chart1_id in chart_ids, "User should see Chart 1"
        # The user should NOT have access to chart 2 (dataset 2)
        assert chart2_id not in chart_ids, "IDOR: User accessed metadata for Chart 2 without permission"

    def test_get_datasets_vulnerability(self):
        self.login(self.username, "password")

        # Re-fetch dashboard ID to ensure session consistency
        dashboard = db.session.query(Dashboard).filter_by(id=self.dashboard.id).one()

        uri = f"api/v1/dashboard/{dashboard.id}/datasets"
        rv = self.client.get(uri)
        assert rv.status_code == 200

        data = rv.json["result"]
        dataset_ids = [d["id"] for d in data]

        # Re-fetch dataset IDs to avoid DetachedInstanceError
        dataset1_id = self.dataset1.id
        dataset2_id = self.dataset2.id

        assert dataset1_id in dataset_ids, "User should see Dataset 1"
        # The user should NOT have access to dataset 2
        assert dataset2_id not in dataset_ids, "IDOR: User accessed metadata for Dataset 2 without permission"
