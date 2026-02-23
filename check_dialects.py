from sqlglot import parse_one, exp

sql = "WITH t AS (SELECT 1) VALUES ((SELECT * FROM t))"
dialects = ["postgres", "mysql", "sqlite", "duckdb", "trino"]

for dialect in dialects:
    try:
        print(f"Testing {dialect}...")
        parse_one(sql, read=dialect)
        print(f"  SUCCESS")
    except Exception as e:
        print(f"  FAILED: {e}")
