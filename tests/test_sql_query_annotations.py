"""The security workflow runs bandit at medium severity and confidence (.github/workflows/security.yml),
and bandit's B608 flags, at that level, an f-string, concatenated or .format()-ed SQL statement passed
straight to execute(). Every such query interpolates only code constants, never user input, and
carries `# nosec B608` on a line of its string, where bandit reads it, so the gate stays green."""

import ast
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The workflow's --exclude list, and directories that hold no first-party Python.
EXCLUDED = {".git", "tests", "eval", "demo", "node_modules", "venv", ".venv", "__pycache__"}
# bandit's statement pattern (bandit/plugins/injection_sql.py).
SQL = re.compile(
    r"(select\s.*from\s|delete\s+from\s|insert\s+into\s.*values\s|update\s.*set\s)", re.IGNORECASE | re.DOTALL
)


def _built_queries(tree):
    """The SQL statements built from strings and passed straight to execute() or executemany()."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        if name not in ("execute", "executemany"):
            continue
        query = node.args[0]
        if isinstance(query, ast.JoinedStr):
            text = "".join(part.value for part in query.values if isinstance(part, ast.Constant))
        elif isinstance(query, ast.BinOp) or (
            isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr in ("format", "replace")
        ):
            text = ast.unparse(query)
        else:
            continue
        if SQL.search(text):
            yield query


def _nosec_b608_lines(source):
    return {
        token.start[0]
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT and re.match(r"#\s*nosec\b.*\bB608\b", token.string)
    }


def test_every_built_sql_query_carries_a_b608_annotation_bandit_reads():
    found, unannotated = 0, []
    for path in sorted(ROOT.rglob("*.py")):
        relative = path.relative_to(ROOT)
        if EXCLUDED.intersection(relative.parts) or relative.as_posix().startswith("landing/assets/"):
            continue
        source = path.read_text(encoding="utf-8")
        annotated = _nosec_b608_lines(source)
        for query in _built_queries(ast.parse(source)):
            found += 1
            if not annotated & set(range(query.lineno, query.end_lineno + 1)):
                unannotated.append(f"{relative.as_posix()}:{query.lineno}")
    assert found, "the scan found no built queries: it no longer sees what bandit sees"
    assert not unannotated, unannotated
