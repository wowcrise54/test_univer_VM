#!/usr/bin/env python3
"""Ротация, очистка и оценка размера логов приложения MPVM по компонентам.

Приложение пишет JSON-строки в общий каталог (см. app/diagnostics.py):

    <log_dir>/<компонент>.jsonl         активный журнал
    <компонент>.jsonl.1 … .<N>          ротированные копии (RotatingFileHandler)

Настройки — те же переменные окружения приложения (DiagnosticsConfig.from_env),
поддерживается .env в корне репозитория (без перезаписи уже заданных):
    MPVM_LOG_DIR                          каталог логов (по умолчанию output/logs)
    MPVM_LOG_MAX_BYTES                    максимум на файл, 100 МБ
    MPVM_LOG_BACKUP_COUNT                 максимум ротированных копий, 10
    MPVM_LOG_RETENTION_DAYS               срок хранения журналов, 14 дней
    MPVM_DEBUG_PAYLOAD_RETENTION_HOURS    срок хранения debug-payloads, 24 часа

Команды:
    report      размеры журнала каждого компонента приложения (по умолчанию)
    cleanup     удаление старых файлов и избыточных ротированных копий
    rotate      принудительная ротация активных журналов
    maintain    cleanup + rotate + отчёт «до/после»

Примеры:
    python scripts/rotate-app-logs.py report
    python scripts/rotate-app-logs.py report --json
    python scripts/rotate-app-logs.py cleanup --dry-run
    python scripts/rotate-app-logs.py maintain
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Зеркало CHANNEL_FILES + errors.jsonl из app/diagnostics.py — держите в синхроне.
COMPONENTS: dict[str, str] = {
    "app": "app.jsonl",
    "database": "database.jsonl",
    "mpvm-http": "mpvm-http.jsonl",
    "asset-card-build": "asset-card-build.jsonl",
    "frontend": "frontend.jsonl",
    "debug-payloads": "debug-payloads.jsonl",
    "errors": "errors.jsonl",
}
DEBUG_PREFIX = "debug-"
UNITS = ("Б", "КБ", "МБ", "ГБ", "ТБ")
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 10
DEFAULT_RETENTION_DAYS = 14
DEFAULT_PAYLOAD_RETENTION_HOURS = 24


@dataclass(frozen=True)
class Config:
    log_dir: Path
    max_bytes: int
    backup_count: int
    retention_days: int
    payload_retention_hours: int


@dataclass
class ComponentStats:
    name: str
    active: Path | None = None
    backups: list[Path] = field(default_factory=list)
    extra: list[Path] = field(default_factory=list)

    @property
    def files(self) -> list[Path]:
        return [f for f in ([self.active] if self.active else []) + self.backups + self.extra if f is not None]

    @property
    def active_bytes(self) -> int:
        return self.active.stat().st_size if self.active else 0

    @property
    def rotated_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.backups)

    @property
    def total_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.files)

    @property
    def oldest(self) -> float | None:
        mtimes = [f.stat().st_mtime for f in self.files]
        return min(mtimes) if mtimes else None


@dataclass
class Removal:
    path: Path
    reason: str


def load_env_file(path: Path) -> None:
    """Мини-аналог load_dotenv(override=False): .env уступает уже заданным переменным."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _resolve_relative(raw: Path) -> Path:
    cwd = Path.cwd()
    if (cwd / raw).is_dir():
        return (cwd / raw).resolve()
    if (REPO_ROOT / raw).is_dir():
        return (REPO_ROOT / raw).resolve()
    return (cwd / raw).resolve()


def build_config(args: argparse.Namespace) -> Config:
    load_env_file(REPO_ROOT / ".env")
    if args.log_dir:
        log_dir = Path(args.log_dir).expanduser()
    else:
        raw = Path(os.getenv("MPVM_LOG_DIR", "output/logs")).expanduser()
        log_dir = raw if raw.is_absolute() else _resolve_relative(raw)
    return Config(
        log_dir=log_dir,
        max_bytes=_env_int("MPVM_LOG_MAX_BYTES", DEFAULT_MAX_BYTES, 1024, 2**31 - 1),
        backup_count=_env_int("MPVM_LOG_BACKUP_COUNT", DEFAULT_BACKUP_COUNT, 1, 100),
        retention_days=_env_int("MPVM_LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, 1, 3650),
        payload_retention_hours=_env_int(
            "MPVM_DEBUG_PAYLOAD_RETENTION_HOURS", DEFAULT_PAYLOAD_RETENTION_HOURS, 1, 8760
        ),
    )


def scan(log_dir: Path) -> dict[str, ComponentStats]:
    stats = {name: ComponentStats(name) for name in COMPONENTS}
    stats["other"] = ComponentStats("other")
    if log_dir.is_dir():
        for path in sorted(log_dir.glob("*.jsonl*")):
            matched = False
            for name, stem in COMPONENTS.items():
                if path.name == stem:
                    stats[name].active = path
                    matched = True
                    break
                if path.name.startswith(stem + ".") and path.name[len(stem) + 1 :].isdigit():
                    stats[name].backups.append(path)
                    matched = True
                    break
            if not matched:
                stats["other"].extra.append(path)
    for comp in stats.values():
        comp.backups.sort(key=lambda p: p.name)
    return stats


def human_size(n: float) -> str:
    value = float(n)
    for unit in UNITS:
        if value < 1024 or unit == UNITS[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024


def plural(n: int, one: str, few: str, many: str) -> str:
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return one
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return few
    return many


def format_ts(ts: float | None) -> str:
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def build_warnings(cfg: Config, stats: dict[str, ComponentStats]) -> list[str]:
    warnings: list[str] = []
    now = datetime.now(UTC)
    cap = cfg.max_bytes * (1 + cfg.backup_count)
    for name, comp in stats.items():
        if name == "other" or comp.total_bytes == 0:
            continue
        if comp.total_bytes > cap:
            warnings.append(
                f"{name}: {human_size(comp.total_bytes)} превышает собственный предел приложения "
                f"{human_size(cap)} (макс. размер файла × (1 + число копий)) — нужна ротация"
            )
    payload_cutoff = now - timedelta(hours=cfg.payload_retention_hours)
    for f in stats["debug-payloads"].files:
        if datetime.fromtimestamp(f.stat().st_mtime, UTC) < payload_cutoff:
            warnings.append(f"{f.name}: старше {cfg.payload_retention_hours} ч (retention debug-payloads)")
    regular_cutoff = now - timedelta(days=cfg.retention_days)
    for name, comp in stats.items():
        if name == "other":
            continue
        stale = [
            f
            for f in comp.backups
            if not f.name.startswith(DEBUG_PREFIX)
            and datetime.fromtimestamp(f.stat().st_mtime, UTC) < regular_cutoff
        ]
        if stale:
            warnings.append(f"{name}: {len(stale)} ротированных копий старше {cfg.retention_days} д — удалит cleanup")
    return warnings


def cmd_report(cfg: Config, as_json: bool) -> int:
    if not cfg.log_dir.is_dir():
        print(f"Каталог логов не найден: {cfg.log_dir}")
        return 0
    stats = scan(cfg.log_dir)
    total = sum(c.total_bytes for c in stats.values())
    warnings = build_warnings(cfg, stats)
    if as_json:
        payload = {
            "log_dir": str(cfg.log_dir),
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_bytes": total,
            "components": [
                {
                    "name": name,
                    "active_bytes": comp.active_bytes,
                    "rotated_bytes": comp.rotated_bytes,
                    "total_bytes": comp.total_bytes,
                    "share": comp.total_bytes / total if total else 0.0,
                    "oldest": datetime.fromtimestamp(comp.oldest, UTC).isoformat(timespec="seconds")
                    if comp.oldest is not None
                    else None,
                    "files": [
                        {
                            "name": f.name,
                            "bytes": f.stat().st_size,
                            "mtime": datetime.fromtimestamp(f.stat().st_mtime, UTC).isoformat(
                                timespec="seconds"
                            ),
                        }
                        for f in comp.files
                    ],
                }
                for name, comp in sorted(stats.items(), key=lambda kv: kv[1].total_bytes, reverse=True)
            ],
            "warnings": warnings,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"Каталог логов: {cfg.log_dir}")
    print(
        f"Настройки: retention {cfg.retention_days} д, до {cfg.backup_count} копий на канал, "
        f"макс. файл {human_size(cfg.max_bytes)}"
    )
    print()
    header = f"{'Компонент':<18}{'Активный':>12}{'Ротация':>12}{'Файлов':>8}  {'Старейший':<18}{'Всего':>12}{'Доля':>8}"
    print(header)
    print("-" * len(header))
    for name, comp in sorted(stats.items(), key=lambda kv: kv[1].total_bytes, reverse=True):
        if comp.total_bytes == 0 and name == "other":
            continue
        share = f"{100.0 * comp.total_bytes / total:.1f}%" if total else "—"
        print(
            f"{name:<18}{human_size(comp.active_bytes):>12}{human_size(comp.rotated_bytes):>12}"
            f"{len(comp.files):>8}  {format_ts(comp.oldest):<18}{human_size(comp.total_bytes):>12}{share:>8}"
        )
    print()
    print(f"Всего в журнале: {human_size(total)} ({sum(len(c.files) for c in stats.values())} файлов)")
    if warnings:
        print("\nПредупреждения:")
        for warning in warnings:
            print(f"  - {warning}")
    return 0


def plan_cleanup(cfg: Config) -> list[Removal]:
    if not cfg.log_dir.is_dir():
        return []
    now = datetime.now(UTC)
    regular_cutoff = now - timedelta(days=cfg.retention_days)
    payload_cutoff = now - timedelta(hours=cfg.payload_retention_hours)
    planned: dict[Path, Removal] = {}
    for path in sorted(cfg.log_dir.glob("*.jsonl*")):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        except OSError:
            continue
        if path.name.startswith(DEBUG_PREFIX):
            if mtime < payload_cutoff:
                planned[path] = Removal(path, f"старше {cfg.payload_retention_hours} ч (retention debug-payloads)")
        elif mtime < regular_cutoff:
            planned[path] = Removal(path, f"старше {cfg.retention_days} д (retention)")
    stats = scan(cfg.log_dir)
    for comp in stats.values():
        ordered = sorted(comp.backups, key=lambda p: p.stat().st_mtime, reverse=True)
        for path in ordered[cfg.backup_count :]:
            planned.setdefault(path, Removal(path, f"избыточная копия (хранится до {cfg.backup_count})"))
    return list(planned.values())


def cmd_cleanup(cfg: Config, dry_run: bool) -> int:
    if not cfg.log_dir.is_dir():
        print(f"Каталог логов не найден: {cfg.log_dir}")
        return 0
    planned = plan_cleanup(cfg)
    if not planned:
        print("Очищать нечего.")
        return 0
    total = 0
    for removal in planned:
        size = removal.path.stat().st_size
        total += size
        print(f"  {removal.path.name:<32}{human_size(size):>10}  ({removal.reason})")
    verb = "Было бы удалено" if dry_run else "Удалено"
    print(f"{verb}: {len(planned)} {plural(len(planned), 'файл', 'файла', 'файлов')}, {human_size(total)}")
    if not dry_run:
        for removal in planned:
            try:
                removal.path.unlink()
            except OSError as exc:
                print(f"  не удалось удалить {removal.path.name}: {exc}", file=sys.stderr)
    return 0


def detect_running_app(log_dir: Path) -> str | None:
    """Описание запущенного приложения, держащего логи (контейнер или процесс), либо None."""
    if shutil.which("docker"):
        try:
            proc = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=15
            )
        except (OSError, subprocess.SubprocessError):
            proc = None
        if proc is not None and proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "mpvm-client" in line.strip().lower():
                    return f"docker-контейнер {line.strip()}"
    if shutil.which("lsof"):
        for path in sorted(log_dir.glob("*.jsonl")):
            try:
                proc = subprocess.run(["lsof", "--", str(path)], capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            if proc.returncode == 0 and len(proc.stdout.splitlines()) > 1:
                return f"процесс держит {path.name} открытым"
    return None


def rotate_component(log_dir: Path, name: str, backup_count: int, dry_run: bool) -> list[str]:
    stem = COMPONENTS[name]
    actions: list[str] = []
    active = log_dir / stem
    if not active.exists() and not list(log_dir.glob(f"{stem}.*")):
        return actions
    for i in range(backup_count - 1, 0, -1):
        src = log_dir / f"{stem}.{i}"
        dst = log_dir / f"{stem}.{i + 1}"
        if src.exists():
            actions.append(f"{src.name} → {dst.name}")
            if not dry_run:
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
    first = log_dir / f"{stem}.1"
    if first.exists():
        actions.append(f"{first.name} → удалено (больше {backup_count} копий)")
        if not dry_run:
            first.unlink()
    if active.exists():
        actions.append(f"{active.name} → {first.name}")
        if not dry_run:
            active.rename(first)
            active.touch()
    return actions


def cmd_rotate(cfg: Config, dry_run: bool) -> int:
    if not cfg.log_dir.is_dir():
        print(f"Каталог логов не найден: {cfg.log_dir}")
        return 0
    running = detect_running_app(cfg.log_dir)
    if running:
        print(
            f"Внимание: приложение запущено ({running}). До собственной ротации приложения "
            "новые записи пойдут в только что созданные .jsonl.1."
        )
        print("  Для чистого разрыва: docker compose restart mpvm-client")
    acted = False
    for name in COMPONENTS:
        actions = rotate_component(cfg.log_dir, name, cfg.backup_count, dry_run)
        if actions:
            acted = True
            print(f"{name}:")
            for action in actions:
                print(f"  {action}")
    if not acted:
        print("Ротировать нечего (нет активных журналов).")
    return 0


def _dir_total_bytes(log_dir: Path) -> int:
    if not log_dir.is_dir():
        return 0
    total = 0
    for path in log_dir.glob("*.jsonl*"):
        with contextlib.suppress(OSError):
            total += path.stat().st_size
    return total


def cmd_maintain(cfg: Config, dry_run: bool) -> int:
    before = _dir_total_bytes(cfg.log_dir)
    print("=== До ===")
    cmd_report(cfg, as_json=False)
    print()
    print("=== Очистка ===")
    cmd_cleanup(cfg, dry_run)
    print()
    print("=== Ротация ===")
    cmd_rotate(cfg, dry_run)
    if not dry_run:
        after = _dir_total_bytes(cfg.log_dir)
        print(f"\nОсвобождено: {human_size(before - after)} ({human_size(before)} → {human_size(after)})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ротация, очистка и оценка размера логов MPVM по компонентам"
    )
    parser.add_argument("--log-dir", help="каталог логов (по умолчанию $MPVM_LOG_DIR или output/logs)")
    sub = parser.add_subparsers(dest="command")
    sp_report = sub.add_parser("report", help="размеры журнала каждого компонента (по умолчанию)")
    sp_report.add_argument("--json", action="store_true", help="вывод в JSON")
    sp_cleanup = sub.add_parser("cleanup", help="удалить старые файлы и избыточные ротированные копии")
    sp_cleanup.add_argument("--dry-run", action="store_true", help="только показать, что будет удалено")
    sp_rotate = sub.add_parser("rotate", help="принудительно ротировать активные журналы")
    sp_rotate.add_argument("--dry-run", action="store_true", help="только показать действия")
    sp_maintain = sub.add_parser("maintain", help="cleanup + rotate + отчёт до/после")
    sp_maintain.add_argument("--dry-run", action="store_true", help="только показать действия")
    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "report"
        args.json = False
    cfg = build_config(args)
    if args.command == "report":
        return cmd_report(cfg, args.json)
    if args.command == "cleanup":
        return cmd_cleanup(cfg, args.dry_run)
    if args.command == "rotate":
        return cmd_rotate(cfg, args.dry_run)
    return cmd_maintain(cfg, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
