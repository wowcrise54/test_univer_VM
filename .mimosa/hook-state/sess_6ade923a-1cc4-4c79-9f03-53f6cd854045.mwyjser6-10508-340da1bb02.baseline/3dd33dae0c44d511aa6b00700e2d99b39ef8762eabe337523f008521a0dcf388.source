from __future__ import annotations

import ast
import threading
import unittest
from pathlib import Path

from app import db, main
from app.core.config import Settings
from app.core.runtime import CancellationRegistry, OperationRunner

EXPECTED_API_PATHS = {
    "/api/health",
    "/api/system/status",
    "/api/session",
    "/api/session/connect",
    "/api/scanner-tasks",
    "/api/operations",
    "/api/operations/summary",
    "/api/exports/pdql",
    "/api/reports/vulnerabilities/{report_type}/csv",
    "/api/reports/vulnerabilities/xlsx",
    "/api/assets",
    "/api/asset-groups",
    "/api/asset-cards/local",
    "/api/asset-card-query",
    "/api/vulnerability-passports/local",
    "/api/vulnerabilities/summary",
    "/api/vulnerabilities",
    "/api/vulnerabilities/hosts",
    "/api/diagnostics/frontend",
    "/api/automations/runbooks",
    "/api/automations/schedules",
    "/api/automations/runs",
    "/api/notifications",
    "/api/remediation/cases",
    "/api/remediation/cases/start",
    "/api/remediation/resolution-stats",
    "/api/remediation/summary",
    "/api/remediation/policy",
    "/api/coverage/summary",
    "/api/coverage/assets",
    "/api/vm/overview",
    "/api/vm/workflows",
    "/api/vm/workflows/scan",
}


class ContractTests(unittest.TestCase):
    def test_runtime_image_includes_alembic_assets(self):
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY alembic.ini ./alembic.ini", dockerfile)
        self.assertIn("COPY migrations ./migrations", dockerfile)

    def test_openapi_keeps_public_domain_paths(self):
        schema = main.app.openapi()
        self.assertTrue(EXPECTED_API_PATHS.issubset(schema["paths"]))

    def test_routes_are_grouped_by_domain_tags(self):
        schema = main.app.openapi()
        self.assertEqual(schema["paths"]["/api/session"]["get"]["tags"], ["session"])
        self.assertEqual(schema["paths"]["/api/operations"]["get"]["tags"], ["operations"])
        self.assertEqual(schema["paths"]["/api/asset-card-query"]["post"]["tags"], ["asset-query"])
        self.assertEqual(schema["paths"]["/api/asset-groups"]["get"]["tags"], ["asset-groups"])

    def test_baseline_schema_is_idempotent_and_non_destructive(self):
        statements = db.schema_statements()
        sql = "\n".join(statements).upper()
        self.assertIn("CREATE TABLE IF NOT EXISTS OPERATIONS", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS ASSET_CARDS", sql)
        self.assertNotIn("DROP TABLE", sql)


class RuntimeTests(unittest.TestCase):
    def test_cancellation_registry_owns_tokens(self):
        registry = CancellationRegistry()
        token = registry.register("asset-card", "job-1")
        self.assertIsInstance(token, threading.Event)
        self.assertTrue(registry.cancel("asset-card", "job-1"))
        self.assertTrue(token.is_set())
        registry.remove("asset-card", "job-1")
        self.assertFalse(registry.cancel("asset-card", "job-1"))

    def test_operation_runner_can_restart_after_shutdown(self):
        runner = OperationRunner({"test": 1})
        self.assertEqual(runner.submit("test", lambda: 42).result(timeout=2), 42)
        runner.shutdown()
        runner.start()
        self.assertEqual(runner.submit("test", lambda: 43).result(timeout=2), 43)
        runner.shutdown()

    def test_settings_reject_invalid_worker_limits(self):
        with self.assertRaises(ValueError):
            Settings(background_request_limit=0)


class ArchitectureBoundaryTests(unittest.TestCase):
    """Static checks that keep the persistence/repositories/api layering intact."""

    @classmethod
    def _app_files(cls):
        root = Path(__file__).resolve().parent.parent / "app"
        return sorted(p for p in root.rglob("*.py") if ".venv" not in p.parts)

    @classmethod
    def _module_map(cls):
        root = Path(__file__).resolve().parent.parent / "app"
        modules = {}
        for p in cls._app_files():
            dotted = ".".join(p.relative_to(root.parent).with_suffix("").parts)
            modules[dotted] = p
        return modules

    @classmethod
    def _import_edges(cls):
        """module dotted name -> set of top-level imported app.* modules."""
        edges: dict[str, set[str]] = {}
        for dotted, path in cls._module_map().items():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            pkg = dotted.rsplit(".", 1)[0]
            targets: set[str] = set()
            for node in tree.body:
                if not isinstance(node, ast.ImportFrom) or node.level == 0:
                    continue
                base = node.module or ""
                if node.level == 1:
                    resolved = base or pkg
                else:
                    up = pkg.split(".")[: -(node.level - 1)]
                    resolved = ".".join(up + ([base] if base else []))
                if resolved.startswith("app"):
                    targets.add(resolved)
            edges[dotted] = targets
        return edges

    def test_repositories_do_not_import_app_db(self):
        root = Path(__file__).resolve().parent.parent / "app"
        offenders = []
        for p in (root / "repositories").rglob("*.py"):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            pkg = ".".join(p.relative_to(root).with_suffix("").parts)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level == 0:
                    continue
                base = node.module or ""
                if node.level == 1:
                    resolved = base or pkg
                else:
                    up = pkg.split(".")[: -(node.level - 1)]
                    resolved = ".".join(up + ([base] if base else []))
                if resolved == "app.db":
                    offenders.append(f"{p.name}:{node.lineno}")
        self.assertEqual(offenders, [], "repositories must not import the app.db facade")

    def test_repositories_do_not_import_services_or_api(self):
        edges = self._import_edges()
        offenders = []
        for module, targets in edges.items():
            if not module.startswith("app.repositories"):
                continue
            for target in targets:
                if target.startswith(("app.services", "app.api")):
                    offenders.append(f"{module} -> {target}")
        self.assertEqual(offenders, [])

    def test_persistence_does_not_import_repositories(self):
        edges = self._import_edges()
        offenders = []
        for module, targets in edges.items():
            if not module.startswith("app.persistence"):
                continue
            for target in targets:
                if target.startswith("app.repositories"):
                    offenders.append(f"{module} -> {target}")
        self.assertEqual(offenders, [])

    def test_no_circular_imports_between_app_modules(self):
        edges = self._import_edges()
        cycles: list[list[str]] = []

        def dfs(start: str, current: str, path: list[str]) -> None:
            for nxt in sorted(edges.get(current, ())):
                if nxt == start and len(path) >= 2:
                    cycles.append(path + [start])
                elif nxt not in path and nxt > start:
                    dfs(start, nxt, path + [nxt])

        for start in sorted(edges):
            dfs(start, start, [start])
        self.assertEqual(cycles, [], f"top-level import cycles: {cycles}")

    def test_db_facade_is_thin_and_complete(self):
        import importlib

        db_mod = importlib.import_module("app.db")
        tree = ast.parse((Path(__file__).resolve().parent.parent / "app" / "db.py").read_text(encoding="utf-8"))
        local_defs = [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        ]
        self.assertEqual(local_defs, [], "app/db.py must not define its own implementations")
        all_node = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "__all__" for t in node.targets)
            ),
            None,
        )
        self.assertIsNotNone(all_node, "app/db.py must keep its __all__ compatibility list")
        all_names = [el.value for el in all_node.value.elts if isinstance(el, ast.Constant)]
        missing = [name for name in all_names if not hasattr(db_mod, name)]
        self.assertEqual(missing, [], f"facade __all__ names must resolve: {missing}")

    def test_no_duplicated_top_level_definitions(self):
        """Every public facade name must be defined in exactly one module (no double copies)."""
        root = Path(__file__).resolve().parent.parent / "app"
        db_tree = ast.parse((root / "db.py").read_text(encoding="utf-8"))
        all_node = next(
            node
            for node in db_tree.body
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", None) == "__all__" for t in node.targets)
        )
        public_names = [el.value for el in all_node.value.elts if isinstance(el, ast.Constant)]
        # Names that already existed in two places before the db.py split (db.py + one other
        # module, e.g. api handlers or private helpers); the split must not add new copies.
        preexisting_duplicate_owners = {
            "_page_bounds": 2,
            "create_asset_card_build_job": 2,
            "delete_vulnerability_passport": 2,
            "import_csv_text": 2,
            "labelize_asset_key": 2,
        }
        owners: dict[str, list[str]] = {name: [] for name in public_names}
        for p in self._app_files():
            if p.name == "db.py":
                continue
            tree = ast.parse(p.read_text(encoding="utf-8"))
            defined = set()
            for node in tree.body:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    defined.add(node.name)
                elif isinstance(node, ast.Assign | ast.AnnAssign):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    defined.update(tg.id for tg in targets if isinstance(tg, ast.Name))
            for name in defined & set(owners):
                owners[name].append(str(p.relative_to(root)))
        problems = {
            name: files
            for name, files in owners.items()
            if len(files) != preexisting_duplicate_owners.get(name, 1)
        }
        self.assertEqual(problems, {}, "each public name must keep its baseline definition count")


if __name__ == "__main__":
    unittest.main()
