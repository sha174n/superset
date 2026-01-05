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

import pytest
from pytest_mock import MockerFixture
from superset.db_engine_specs import load_engine_specs

def test_get_prequeries_security(mocker: MockerFixture) -> None:
    """
    Scan all DB engine specs to ensure `get_prequeries` is secure against SQL injection.

    This test iterates over all available engine specs, injects a malicious payload
    into `catalog`, `schema`, and `username` (for impersonation), and verifies that
    the payload is not present in the generated SQL in its raw, unescaped form.
    """

    # Malicious payload designed to break out of strings
    # We use a unique marker to easily check for presence
    marker = "INJECTION_MARKER"
    payload = f'"{marker}"; --'

    # Mock database object
    database = mocker.MagicMock()

    # Mock quote_identifier to simply wrap in quotes (or whatever is safe)
    # The key is that the engine spec should call this.
    # If the engine spec calls this, the output will contain the QUOTED payload.
    # If it fails to call this, it will contain the RAW payload.
    # Note: Real `quote_identifier` would escape quotes.
    # We simulate safe quoting here.
    def safe_quote(s: str) -> str:
        # Use simple string concatenation or double quotes to avoid syntax errors in older Python
        return f'"{s.replace("`", "``").replace("\"", "\"\"")}"'

    database.quote_identifier = safe_quote
    database.impersonate_user = True
    database.get_effective_user.return_value = payload

    engine_specs = load_engine_specs()

    for engine_spec in engine_specs:
        # Test catalog/schema injection
        try:
            prequeries = engine_spec.get_prequeries(
                database,
                catalog=payload,
                schema=payload
            )
        except Exception:
            # Some engines might raise errors if params are invalid, which is fine (secure)
            prequeries = []

        for sql in prequeries:
            # Check if the raw payload exists in the SQL
            # If the engine properly quotes, `payload` should NOT be in `sql`
            # because the internal quotes would be escaped (e.g., ""INJECTION_MARKER""; --)
            # or wrapped (e.g., "`"INJECTION_MARKER"; --`")

            # Use a slightly relaxed check:
            # The raw marker "INJECTION_MARKER"; -- shouldn't appear unescaped.
            # But exact string matching is tricky because of different quoting styles.

            # Better check:
            # If we used `quote_identifier`, the payload string appearing in SQL
            # should satisfy the `safe_quote` transformation.
            # If the RAW payload appears exactly as is, it's likely an injection.

            # However, simpler check:
            # The payload contains a double quote and a semicolon.
            # If it's properly escaped, the double quote should be doubled or escaped.

            if payload in sql:
                # If the exact payload string is found, it means it wasn't escaped.
                # One exception: if the engine uses single quotes for identifiers?
                # But our payload uses double quotes.

                # Check for false positives: maybe the engine wrapped it in single quotes?
                # ' "INJECTION_MARKER"; -- ' -> Safe in some dialects, but usually identifiers use ".

                # Let's inspect the failure if it happens.
                pytest.fail(
                    f"SQL Injection vulnerability detected in {engine_spec.__name__}. "
                    f"Generated SQL: {sql} contains raw payload: {payload}"
                )
