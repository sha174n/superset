from sqlglot import parse_one, exp

sql = "WITH t AS (SELECT 1) INSERT INTO t2 VALUES ((SELECT * FROM t))"
try:
    statement = parse_one(sql)
    print("SUCCESS")
except Exception as e:
    print(f"FAILED: {e}")
