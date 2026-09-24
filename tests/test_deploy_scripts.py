"""Local runs of deploy/deploy.sh and backup.sh against a throwaway repository and database.

systemctl, curl and the other host commands are shell functions that record every call, so the tests can
check what a run would do to the server without touching one.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
UNITS = {"shieldbot", "shieldbot-bot"}
KEY = "ROBINHOOD_RECORDER_PRIVATE_KEY"
PYTHON = Path(sys.executable).as_posix()

STUBS = r"""
log() { printf '%s\n' "$*" >> "$STATE/calls"; }
id() { echo 0; }
flock() { return 0; }
sleep() { :; }
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nstub 1 1 99999999 1%% /\n'; }
journalctl() { log journalctl "$@"; }
scp() { log scp "$@"; }
git() { log git "$@"; command git "$@"; }
systemctl() {
  log systemctl "$@"
  case $1 in
    stop) rm -f "$STATE/active-$2" ;;
    start) touch "$STATE/active-$2" ;;
    is-active) if [ -e "$STATE/active-$2" ]; then echo active; else echo inactive; return 3; fi ;;
    cat) cat "$STATE/unit-$2" ;;
    show)
      case $3 in
        MainPID) if [ -e "$STATE/active-$5" ]; then echo 4242; else echo 0; fi ;;
        NRestarts) echo 0 ;;
      esac ;;
  esac
}
curl() {
  log curl "$@"
  [ -e "$STATE/active-shieldbot" ] || return 7
  case ${!#} in
    */api/health)
      # health-fail-call names the one /api/health request (1, 2, ...) that fails, as curl -f would.
      calls=$(( $(cat "$STATE/health-calls" 2>/dev/null || echo 0) + 1 ))
      echo "$calls" > "$STATE/health-calls"
      [ "$calls" != "$(cat "$STATE/health-fail-call" 2>/dev/null || true)" ] || return 22
      cat "$STATE/health.json" ;;
    */api/stats) echo '{"contracts_scanned": 1}' ;;
  esac
}
"""


@pytest.fixture
def bash():
    executable = shutil.which("bash")
    if executable is None:
        pytest.skip("Bash is required for deployment script tests")
    return executable


def run_script(bash, script: Path, state: Path, *args, **env):
    environment = {**os.environ, "STATE": state.as_posix(), **env}
    # Resolve coreutils from bash's own directory first (on Windows, System32 has an unrelated find.exe).
    environment["PATH"] = os.pathsep.join([str(Path(bash).parent), environment["PATH"]])
    result = subprocess.run(
        [bash, "--noprofile", "--norc", script.as_posix(), *args],
        env=environment,
        capture_output=True,
        timeout=120,
    )
    return (
        result.returncode,
        result.stdout.decode("utf-8", "replace"),
        result.stderr.decode("utf-8", "replace"),
    )


def write_script(path: Path, source: str, replacements: dict) -> Path:
    source = source.replace("\r\n", "\n")
    for old, new in replacements.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    path.write_text(STUBS + source, encoding="utf-8", newline="\n")
    return path


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def git(cwd: Path, *args) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def rows(db: Path) -> list:
    connection = sqlite3.connect(db)
    try:
        return [row[0] for row in connection.execute("SELECT id FROM scans ORDER BY id")]
    finally:
        connection.close()


class Server:
    """A fake /opt/shieldbot: a git checkout of `old` whose origin also holds `target`."""

    def __init__(self, tmp: Path, bash: str):
        self.tmp, self.bash = tmp, bash
        self.state = tmp / "state"
        self.state.mkdir()
        self.app = tmp / "app"
        origin = tmp / "origin.git"
        git(tmp, "init", "-q", "--bare", str(origin))

        git(tmp, "init", "-q", str(self.app))
        git(self.app, "config", "core.autocrlf", "false")
        (self.app / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
        (self.app / "utils").mkdir()
        (self.app / "utils" / "chain_info.py").write_text(
            'CHAIN_INFO = {56: {"name": "BSC"}, 4663: {"name": "Robinhood Chain"}}\n',
            encoding="utf-8",
        )
        git(self.app, "add", ".")
        git(self.app, "commit", "-q", "-m", "old")
        git(self.app, "remote", "add", "origin", str(origin))
        git(self.app, "push", "-q", "origin", "HEAD:refs/heads/main")
        self.old = git(self.app, "rev-parse", "HEAD")

        # The target is made in another clone, so the server only has it after `git fetch`.
        dev = tmp / "dev"
        git(tmp, "clone", "-q", "-b", "main", str(origin), str(dev))
        git(dev, "config", "core.autocrlf", "false")
        (dev / "NEW_SCHEMA").write_text("the new code writes to the database\n", encoding="utf-8")
        git(dev, "add", ".")
        git(dev, "commit", "-q", "-m", "new")
        git(dev, "push", "-q", "origin", "HEAD:refs/heads/main")
        self.target = git(dev, "rev-parse", "HEAD")

        self.db = self.app / "shieldbot.db"
        connection = sqlite3.connect(self.db)
        connection.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO scans VALUES (1)")
        connection.commit()
        connection.close()
        (self.app / ".env").write_text("TELEGRAM_BOT_TOKEN=unused\n", encoding="utf-8")

        bin_dir = self.app / "venv" / "bin"
        bin_dir.mkdir(parents=True)
        write_executable(bin_dir / "python", f'#!/bin/sh\nexec "{PYTHON}" "$@"\n')
        # pip stands in for the new code's first run: on the target commit it writes a row.
        migrate = (
            "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); "
            "db.execute('INSERT OR IGNORE INTO scans VALUES (99)'); db.commit(); db.close()"
        )
        write_executable(
            bin_dir / "pip",
            f'#!/bin/sh\nprintf "pip %s\\n" "$*" >> "$STATE/calls"\n'
            f'if [ -f "{self.app.as_posix()}/NEW_SCHEMA" ]; then '
            f'"{PYTHON}" -c "{migrate}" "{self.db.as_posix()}"; fi\n',
        )

        (self.state / "unit-shieldbot").write_text(
            "[Service]\nExecStart=uvicorn api:app\n", encoding="utf-8"
        )
        (self.state / "unit-shieldbot-bot").write_text(
            "[Service]\nEnvironmentFile=/opt/shieldbot/.env\nExecStart=python bot.py\n",
            encoding="utf-8",
        )
        (self.state / "active-shieldbot").touch()
        (self.state / "active-shieldbot-bot").touch()
        self.set_health([56, 4663])
        self.environ = tmp / "proc" / "4242" / "environ"
        self.environ.parent.mkdir(parents=True)
        self.environ.write_bytes(b"PATH=/usr/bin\x00HOME=/root\x00")

        self.script = write_script(
            tmp / "deploy.sh",
            (ROOT / "deploy" / "deploy.sh").read_text(encoding="utf-8"),
            {
                "APP=/opt/shieldbot\n": f"APP={self.app.as_posix()}\n",
                "BACKUP=/root/shieldbot-backup-": f"BACKUP={tmp.as_posix()}/shieldbot-backup-",
                "LOCK=/run/shieldbot-deploy.lock": f"LOCK={tmp.as_posix()}/deploy.lock",
                '"/proc/$pid/environ"': f'"{tmp.as_posix()}/proc/$pid/environ"',
            },
        )

    def set_health(self, chains) -> None:
        payload = {"status": "ok", "service": "shieldai-firewall", "supported_chains": chains}
        (self.state / "health.json").write_text(json.dumps(payload), encoding="utf-8")

    def run(self, *args):
        return run_script(self.bash, self.script, self.state, *args)

    def head(self) -> str:
        return git(self.app, "rev-parse", "HEAD")

    def calls(self) -> list:
        path = self.state / "calls"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def backups(self) -> list:
        return sorted(self.tmp.glob("shieldbot-backup-*"))

    def active(self) -> set:
        return {path.name[len("active-") :] for path in self.state.glob("active-*")}


@pytest.fixture
def server(tmp_path, bash):
    return Server(tmp_path, bash)


def first(calls: list, prefix: str) -> int:
    return next(i for i, call in enumerate(calls) if call.startswith(prefix))


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--check"],
        ["--check", "main"],
        ["--cutover", "abc123"],
        ["--cutover", "0123456; rm -rf /"],
        ["--deploy", "0123456"],
        ["--rollback"],
    ],
)
def test_bad_arguments_stop_before_any_command(server, args):
    code, _, err = server.run(*args)
    assert code == 2
    assert "usage:" in err
    assert server.calls() == []


def test_check_is_read_only_and_says_go(server):
    database = server.db.read_bytes()
    code, out, err = server.run("--check", server.target[:7])
    assert code == 0, err
    assert "GO" in out and "rollback point" in out
    assert "1 commit(s) ahead" in out
    calls = server.calls()
    assert any(call.startswith("git -C") and " fetch " in call for call in calls)
    for forbidden in ("systemctl stop", "systemctl start", "pip", "curl"):
        assert not [call for call in calls if call.startswith(forbidden)], forbidden
    assert not [call for call in calls if " checkout " in call]
    assert server.head() == server.old
    assert server.db.read_bytes() == database
    assert server.backups() == []


@pytest.mark.parametrize(
    "where", ["shared .env", "unit loads recorder.env", "unit sets the key", "bot process"]
)
def test_check_refuses_when_the_bot_can_see_the_recorder_key(server, where):
    secret = "0x" + "5e" * 32
    unit = server.state / "unit-shieldbot-bot"
    if where == "shared .env":
        (server.app / ".env").write_text(f"{KEY}={secret}\n", encoding="utf-8")
    elif where == "unit loads recorder.env":
        unit.write_text(
            unit.read_text() + "EnvironmentFile=/etc/shieldbot/recorder.env\n", encoding="utf-8"
        )
    elif where == "unit sets the key":
        unit.write_text(unit.read_text() + f'Environment="{KEY}={secret}"\n', encoding="utf-8")
    else:
        server.environ.write_bytes(server.environ.read_bytes() + f"{KEY}={secret}\x00".encode())
    code, out, err = server.run("--check", server.target)
    assert code == 1
    assert "NO-GO" in err
    assert "rollback point" not in out
    assert secret not in out + err


def test_check_fails_closed_when_the_bot_environment_cannot_be_read(server):
    server.environ.unlink()
    code, _, err = server.run("--check", server.target)
    assert code == 1
    assert "could not read the environment" in err


def test_check_refuses_a_commit_that_is_not_on_origin(server):
    code, _, err = server.run("--check", "0123456789abcdef0123456789abcdef01234567")
    assert code == 1
    assert "not a commit" in err


def test_check_refuses_modified_tracked_files(server):
    (server.app / "requirements.txt").write_text(
        "fastapi\nedited-on-the-server\n", encoding="utf-8"
    )
    code, _, err = server.run("--check", server.target)
    assert code == 1
    assert "modified tracked files" in err


def test_cutover_deploys_in_order_and_touches_only_its_two_units(server):
    code, out, err = server.run("--cutover", server.target[:10])
    assert code == 0, err + out
    assert server.head() == server.target
    assert "DEPLOYED" in out and "--rollback" in out

    [backup] = server.backups()
    assert (backup / "ROLLBACK_COMMIT").read_text(encoding="utf-8").strip() == server.old
    assert rows(backup / "shieldbot.db") == [1]
    assert not list(backup.glob("*.partial"))
    assert not (backup / "env.bak").exists()
    assert rows(server.db) == [1, 99]

    calls = server.calls()
    service = [call for call in calls if call.startswith(("systemctl stop", "systemctl start"))]
    assert service == [
        "systemctl stop shieldbot-bot",
        "systemctl stop shieldbot",
        "systemctl start shieldbot",
        "systemctl start shieldbot-bot",
    ]
    for call in calls:
        if call.startswith("systemctl"):
            assert call.split()[-1] in UNITS, call
    checkout = next(i for i, call in enumerate(calls) if " checkout " in call)
    assert first(calls, "systemctl stop shieldbot") < checkout < first(calls, "pip")
    assert first(calls, "pip") < first(calls, "systemctl start shieldbot") < first(calls, "curl")
    assert first(calls, "curl") < first(calls, "systemctl start shieldbot-bot")
    assert server.active() == UNITS


def test_cutover_is_idempotent(server):
    assert server.run("--cutover", server.target)[0] == 0
    code, out, err = server.run("--cutover", server.target)
    assert code == 0, err + out
    assert "already deployed" in out
    assert server.head() == server.target


def test_a_failure_inside_a_command_substitution_rolls_back_once(server):
    # The second /api/health request is the one inside check_health's $(...). The ERR trap is inherited by that
    # subshell, and only the main shell may act on it.
    (server.state / "health-fail-call").write_text("2", encoding="utf-8")
    code, _, err = server.run("--cutover", server.target)
    assert code == 1
    assert "rolled back" in err
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.calls().count("systemctl stop shieldbot-bot") == 2
    assert server.active() == UNITS


def test_cutover_rolls_back_when_health_misses_a_chain(server):
    server.set_health([56])
    code, out, err = server.run("--cutover", server.target)
    assert code == 1
    assert "expected [56, 4663]" in err
    assert "rolled back" in err
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.active() == UNITS
    assert not (server.app / "NEW_SCHEMA").exists()


def test_manual_rollback_restores_the_saved_commit_and_database(server):
    assert server.run("--cutover", server.target)[0] == 0
    [backup] = server.backups()
    code, out, err = server.run("--rollback", backup.as_posix())
    assert code == 0, err + out
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.active() == UNITS


def test_rollback_refuses_a_directory_without_a_saved_commit(server):
    empty = server.tmp / "shieldbot-backup-empty"
    empty.mkdir()
    code, _, err = server.run("--rollback", empty.as_posix())
    assert code == 1
    assert "ROLLBACK_COMMIT" in err
    assert not [call for call in server.calls() if call.startswith("systemctl stop")]


class Backup:
    def __init__(self, tmp: Path, bash: str):
        self.tmp, self.bash = tmp, bash
        self.state = tmp / "state"
        self.state.mkdir()
        self.db = tmp / "shieldbot.db"
        self.dir = tmp / "backups"
        self.script = write_script(
            tmp / "backup.sh",
            (ROOT / "backup.sh").read_text(encoding="utf-8"),
            {
                "DB=/opt/shieldbot/shieldbot.db": f"DB={self.db.as_posix()}",
                "BACKUP_DIR=/opt/shieldbot/backups": f"BACKUP_DIR={self.dir.as_posix()}",
                "PY=/opt/shieldbot/venv/bin/python3": f"PY={PYTHON}",
            },
        )

    def run(self, **env):
        return run_script(self.bash, self.script, self.state, **env)

    def calls(self) -> list:
        path = self.state / "calls"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


@pytest.fixture
def backup(tmp_path, bash):
    return Backup(tmp_path, bash)


def test_backup_takes_a_consistent_copy_while_the_database_is_in_use(backup):
    live = sqlite3.connect(backup.db)
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY)")
    live.execute("INSERT INTO scans VALUES (1)")
    live.commit()
    # The committed row still sits in the WAL while this connection stays open.
    try:
        code, out, err = backup.run()
    finally:
        live.close()
    assert code == 0, err
    [copy] = backup.dir.glob("shieldbot_*.db")
    # Header bytes 18 and 19 are 1 for a rollback-journal database: the copy stands alone, with no WAL to carry.
    assert copy.read_bytes()[18:20] == b"\x01\x01"
    assert rows(copy) == [1]
    assert "Backup saved" in out
    assert sorted(path.name for path in backup.dir.iterdir()) == [copy.name]
    assert backup.calls() == []


def test_backup_prunes_only_its_own_copies_older_than_keep_days(backup):
    sqlite3.connect(backup.db).close()
    backup.dir.mkdir()
    now = time.time()
    for name, days in (("shieldbot_old.db", 4), ("shieldbot_recent.db", 2), ("unrelated.db", 30)):
        path = backup.dir / name
        path.write_bytes(b"")
        os.utime(path, (now - days * 86400, now - days * 86400))
    code, _, err = backup.run(KEEP_DAYS="3")
    assert code == 0, err
    names = {path.name for path in backup.dir.iterdir()}
    assert "shieldbot_old.db" not in names
    assert {"shieldbot_recent.db", "unrelated.db"} <= names
    assert len([name for name in names if name.startswith("shieldbot_")]) == 2


def test_backup_copies_off_box_only_when_asked(backup):
    sqlite3.connect(backup.db).close()
    code, out, err = backup.run(BACKUP_REMOTE="backup@example.net:/srv/shieldbot/")
    assert code == 0, err
    [copy] = backup.dir.glob("shieldbot_*.db")
    [call] = backup.calls()
    assert call.startswith("scp ") and call.endswith(
        f"{copy.as_posix()} backup@example.net:/srv/shieldbot/"
    )
    assert "BatchMode=yes" in call


def test_backup_never_creates_a_missing_database(backup):
    code, _, err = backup.run()
    assert code != 0
    assert not backup.db.exists()
    assert not list(backup.dir.glob("shieldbot_*"))


@pytest.mark.parametrize("keep_days", ["0", "7d", "-1"])
def test_backup_rejects_a_bad_keep_days(backup, keep_days):
    sqlite3.connect(backup.db).close()
    code, _, err = backup.run(KEEP_DAYS=keep_days)
    assert code == 2
    assert "KEEP_DAYS" in err
    assert not backup.dir.exists()
