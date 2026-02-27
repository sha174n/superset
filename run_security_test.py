import os
import unittest

# Ensure configuration is set
os.environ["SUPERSET_CONFIG"] = "tests.integration_tests.superset_test_config"

from superset import create_app
from tests.integration_tests.dashboards.security_tests import TestDashboardChartsSecurity

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        unittest.main()
