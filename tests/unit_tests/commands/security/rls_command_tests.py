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
from unittest.mock import MagicMock, patch

import pytest
from marshmallow import ValidationError

from superset.commands.security.create import CreateRLSRuleCommand
from superset.commands.security.update import UpdateRLSRuleCommand
from superset.commands.security.exceptions import RLSRuleInvalidError
from superset.exceptions import SupersetSecurityException


@pytest.fixture
def mock_table():
    table = MagicMock()
    table.database.db_engine_spec.engine = "postgresql"
    table.catalog = None
    table.schema = "public"
    return table


@patch("superset.commands.security.create.DatasetDAO")
@patch("superset.commands.security.create.populate_roles")
def test_create_rls_command_subquery_validation(mock_populate, mock_dao, mock_table):
    mock_dao.find_by_ids.return_value = [mock_table]
    
    # Comprehensive attack patterns from the Security Torture Test
    attacks = [
        "1=1 OR EXISTS (SELECT 1 FROM (SELECT table_name FROM information_schema.tables) AS t WHERE 1=1)",
        "id IN (SELECT id FROM ab_user)",
        "1=0 UNION SELECT password FROM ab_user",
        "1=0 UNION ALL SELECT password FROM ab_user",
        "WITH secret AS (SELECT password FROM ab_user) SELECT * FROM secret",
        "1=1 OR EXISTS (sElEcT 1 FrOm ab_user)",
        "1=1 OR EXISTS (\nSELECT\n1\nFROM\nab_user)",
        "1=1 OR EXISTS (SELECT/**/1/**/FROM/**/ab_user)",
        "id = (SELECT max(id) FROM ab_user)",
        "1=1 FROM (SELECT 1) as t",
        "1=1 JOIN (SELECT id FROM ab_user) as u ON 1=1",
        "EXISTS(SELECT 1)",
        "1=1; SELECT 1",
    ]
    
    for clause in attacks:
        data = {
            "name": "test",
            "clause": clause,
            "tables": [1],
            "roles": [1],
        }
        command = CreateRLSRuleCommand(data)
        with pytest.raises(RLSRuleInvalidError) as ex:
            command.validate()
        # Should be caught by either SecurityException or ParseError
        assert any(
            msg in str(ex.value._exceptions[0]) 
            for msg in ["Custom SQL fields cannot contain sub-queries", "Error parsing near", "exactly one statement"]
        )


@patch("superset.commands.security.create.DatasetDAO")
@patch("superset.commands.security.create.populate_roles")
def test_create_rls_command_safe_validation(mock_populate, mock_dao, mock_table):
    mock_dao.find_by_ids.return_value = [mock_table]
    
    # Test safe patterns
    safe_clauses = [
        "gender = 'boy'",
        "age > 10",
        "region IN ('North', 'South')",
        "CASE WHEN a=1 THEN 'yes' ELSE 'no' END = 'yes'",
        "id IN (1, 2, 3)",
        "age * 2 > 10 OR (id > 5 AND id < 10)",
    ]
    
    for clause in safe_clauses:
        data = {
            "name": "test",
            "clause": clause,
            "tables": [1],
            "roles": [1],
        }
        command = CreateRLSRuleCommand(data)
        command.validate() # Should not raise


@patch("superset.commands.security.update.DatasetDAO")
@patch("superset.commands.security.update.RLSDAO")
@patch("superset.commands.security.update.populate_roles")
def test_update_rls_command_subquery_validation(mock_populate, mock_rls_dao, mock_dataset_dao, mock_table):
    mock_dataset_dao.find_by_ids.return_value = [mock_table]
    mock_rls_dao.find_by_id.return_value = MagicMock()
    
    data = {
        "clause": "id IN (SELECT id FROM users)",
        "tables": [1],
    }
    
    command = UpdateRLSRuleCommand(1, data)
    with pytest.raises(RLSRuleInvalidError) as ex:
        command.validate()
    assert "Custom SQL fields cannot contain sub-queries" in str(ex.value._exceptions[0])
