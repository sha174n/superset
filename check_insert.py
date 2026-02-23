from sqlglot import parse_one, exp
from sqlglot.optimizer.scope import traverse_scope

sql = "INSERT INTO t2 VALUES ((SELECT * FROM t1))"
statement = parse_one(sql)
print(f"Statement type: {type(statement)}")

tables = []
for scope in traverse_scope(statement):
    for source in scope.sources.values():
        if isinstance(source, exp.Table):
            tables.append(source.name)

print(f"Tables found by traverse_scope: {tables}")
