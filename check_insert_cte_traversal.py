from sqlglot import parse_one, exp
from sqlglot.optimizer.scope import traverse_scope

sql = "WITH t AS (SELECT * FROM real_table) INSERT INTO t2 VALUES ((SELECT * FROM t))"
statement = parse_one(sql)

tables = []
ctes = set()
for scope in traverse_scope(statement):
    for source in scope.sources.values():
        if isinstance(source, exp.Table):
            tables.append(source.name)
    for cte in scope.ctes:
        ctes.add(cte.alias)

print(f"Tables found by traverse_scope: {tables}")
print(f"CTEs found by traverse_scope: {ctes}")
