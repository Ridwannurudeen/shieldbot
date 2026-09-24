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
df() {
  # app-free-kib sets the free space reported for the app directory only.
  local free=99999999
  [ "${!#}" != "${FAKE_APP:-}" ] || free=$(cat "$STATE/app-free-kib" 2>/dev/null || echo 99999999)
  printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nstub 1 1 %s 1%% /\n' "$free"
}
journalctl() { log journalctl "$@"; }
scp() { log scp "$@"; [ ! -e "$STATE/scp-fails" ]; }
find() {
  # copies-vanish: a backup copy disappears just before it is pruned.
  if [ -e "$STATE/copies-vanish" ] && [ -f "$1" ]; then rm -f "$1"; fi
  command find "$@"
}
git() { log git "$@"; command git "$@"; }
systemctl() {
  log systemctl "$@"
  case $1 in
    stop) rm -f "$STATE/active-$2" ;;
    start)
      touch "$STATE/active-$2"
      # next-pid-<unit> gives the unit a new main process when it starts.
      [ ! -e "$STATE/next-pid-$2" ] || mv "$STATE/next-pid-$2" "$STATE/pid-$2" ;;
    is-active) if [ -e "$STATE/active-$2" ]; then echo active; else echo inactive; return 3; fi ;;
    cat) cat "$STATE/unit-$2" ;;
    show)
      case $3 in
        MainPID) if [ -e "$STATE/active-$5" ]; then cat "$STATE/pid-$5" 2>/dev/null || echo 4242; else echo 0; fi ;;
        NRestarts) echo 0 ;;
      esac ;;
  esac
}
curl() {
  log curl "$@"
  [ -e "$STATE/active-shieldbot" ] || return 7
  case ${!#} in
    */api/health)
      # unhealthy: the API never answers; unhealthy-on-target: it never answers on the target commit.
      [ ! -e "$STATE/unhealthy" ] || return 7
      [ ! -e "$STATE/unhealthy-on-target" ] || [ ! -e "$FAKE_APP/NEW_SCHEMA" ] || return 7
      # health-fail-call names the one /api/health request (1, 2, ...) that fails, as curl -f would.
      calls=$(( $(cat "$STATE/health-calls" 2>/dev/null || echo 0) + 1 ))
      echo "$calls" > "$STATE/health-calls"
      [ "$calls" != "$(cat "$STATE/health-fail-call" 2>/dev/null || true)" ] || return 22
      cat "$STATE/health.json" ;;
    # unready: /api/ready answers 503 on every poll, which curl -f reports as exit 22.
    */api/ready) [ ! -e "$STATE/unready" ] || return 22 ;;
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
        # pip stands in for the new code's first run: on the target commit it writes a row. State files make it
        # edit a tracked file (pip-dirties-tree), fail on the target (pip-fails) or in the restore
        # (pip-fails-on-restore), die half way through `pip freeze` (freeze-truncated), signal the deploy script
        # while it waits (signal-during-pip holds the signal name and fires on every install, the restore's too),
        # or behave like Ctrl-C, which signals the script and kills pip itself (ctrl-c-during-pip).
        migrate = (
            "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); "
            "db.execute('INSERT OR IGNORE INTO scans VALUES (99)'); db.commit(); db.close()"
        )
        app = self.app.as_posix()
        write_executable(
            bin_dir / "pip",
            f"""#!/bin/sh
printf 'pip %s\\n' "$*" >> "$STATE/calls"
if [ "$1" = freeze ]; then
  echo fastapi==0.1
  if [ -e "$STATE/freeze-truncated" ]; then printf 'web3==6'; exit 1; fi
  exit 0
fi
if [ -f "{app}/NEW_SCHEMA" ]; then
  "{PYTHON}" -c "{migrate}" "{self.db.as_posix()}"
  [ ! -e "$STATE/pip-dirties-tree" ] || echo edited >> "{app}/NEW_SCHEMA"
  if [ -e "$STATE/ctrl-c-during-pip" ]; then kill -INT "$PPID"; kill -INT $$; fi
fi
[ ! -e "$STATE/pip-fails-on-restore" ] || [ -f "{app}/NEW_SCHEMA" ] || exit 1
[ ! -e "$STATE/signal-during-pip" ] || kill -"$(cat "$STATE/signal-during-pip")" "$PPID"
if [ -e "$STATE/signal-during-restore-pip" ] && [ ! -f "{app}/NEW_SCHEMA" ]; then
  kill -"$(cat "$STATE/signal-during-restore-pip")" "$PPID"
fi
[ ! -e "$STATE/pip-fails" ] || [ ! -f "{app}/NEW_SCHEMA" ] || exit 1
""",
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
        return run_script(self.bash, self.script, self.state, *args, FAKE_APP=self.app.as_posix())

    def flag(self, name: str, value: str = "") -> None:
        (self.state / name).write_text(value, encoding="utf-8")

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


def test_deploy_does_not_narrow_the_umask_for_the_whole_run():
    # deploy.sh runs as root while the units run as their own user. Under a restrictive umask, git checkout and
    # pip install would write code the API and bot cannot read, and the rollback would do the same to the old
    # code. These tests run as a single user, so only the source can show it. A umask scoped to a subshell,
    # as for the backup directory, is fine.
    source = (ROOT / "deploy" / "deploy.sh").read_text(encoding="utf-8")
    assert not [line for line in source.splitlines() if line.strip().startswith("umask")]


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
    # A clone has origin/HEAD pointing at the default branch; it is not a branch of its own.
    git(server.app, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    code, out, err = server.run("--check", server.target[:7])
    assert code == 0, err
    assert "GO" in out and "rollback point" in out
    assert "1 commit(s) ahead" in out
    assert "\non origin/main\n" in out
    calls = server.calls()
    assert any(call.startswith("git -C") and " fetch " in call for call in calls)
    # A pager would wait for a keypress with nobody at the terminal.
    assert any(" --no-pager log " in call for call in calls)
    for forbidden in ("systemctl stop", "systemctl start", "pip", "curl"):
        assert not [call for call in calls if call.startswith(forbidden)], forbidden
    assert not [call for call in calls if " checkout " in call]
    assert server.head() == server.old
    assert server.db.read_bytes() == database
    assert server.backups() == []


@pytest.mark.parametrize(
    "where",
    [
        "shared .env",
        "shared .env, exported",
        "unit loads recorder.env",
        "unit sets the key",
        "bot process",
    ],
)
def test_check_refuses_when_the_bot_can_see_the_recorder_key(server, where):
    secret = "0x" + "5e" * 32
    unit = server.state / "unit-shieldbot-bot"
    if where == "shared .env":
        (server.app / ".env").write_text(f"{KEY}={secret}\n", encoding="utf-8")
    elif where == "shared .env, exported":
        (server.app / ".env").write_text(f"A=1\n  export {KEY} = {secret}\n", encoding="utf-8")
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


def test_check_accepts_a_shared_env_that_only_mentions_the_key_in_a_comment(server):
    # .env.example documents the key in a comment; a .env copied from it holds no key.
    (server.app / ".env").write_text(
        f"# {KEY} is deliberately NOT set here.\nTELEGRAM_BOT_TOKEN=unused\n", encoding="utf-8"
    )
    code, out, err = server.run("--check", server.target)
    assert code == 0, err
    assert "rollback point" in out


def test_check_fails_closed_when_the_bot_environment_cannot_be_read(server):
    server.environ.unlink()
    code, _, err = server.run("--check", server.target)
    assert code == 1
    assert "could not read the environment" in err


API_UNIT_WITH_KEY = (
    "[Service]\nExecStart=uvicorn api:app\n\n"
    "# /etc/systemd/system/shieldbot.service.d/override.conf\n"
    "[Service]\nEnvironmentFile=/etc/shieldbot/recorder.env\n"
)


@pytest.mark.parametrize(
    "setting",
    [
        "BACKGROUND_WORKERS=external",
        "export BACKGROUND_WORKERS = 'external'  # workers.py sends",
        'background_workers="external"\r',
    ],
)
def test_check_refuses_an_api_that_loads_the_key_when_the_workers_send(server, setting):
    # With BACKGROUND_WORKERS=external the workers unit runs the drain; the key must have moved there.
    (server.app / ".env").write_text(f"TELEGRAM_BOT_TOKEN=unused\n{setting}\n", encoding="utf-8")
    (server.state / "unit-shieldbot").write_text(API_UNIT_WITH_KEY, encoding="utf-8")
    code, out, err = server.run("--check", server.target)
    assert code == 1
    assert "BACKGROUND_WORKERS=external" in err and "recorder.env" in err
    assert "rollback point" not in out


def test_check_accepts_an_api_without_the_key_when_the_workers_send(server):
    (server.app / ".env").write_text(
        "TELEGRAM_BOT_TOKEN=unused\nBACKGROUND_WORKERS=external\n", encoding="utf-8"
    )
    code, out, err = server.run("--check", server.target)
    assert code == 0, err
    assert "does not load the recorder key" in out
    assert "rollback point" in out


@pytest.mark.parametrize(
    "setting", ["", "BACKGROUND_WORKERS=api\n", "# BACKGROUND_WORKERS=external\n"]
)
def test_check_still_lets_the_api_hold_the_key_when_it_runs_the_drain(server, setting):
    (server.app / ".env").write_text(f"TELEGRAM_BOT_TOKEN=unused\n{setting}", encoding="utf-8")
    (server.state / "unit-shieldbot").write_text(API_UNIT_WITH_KEY, encoding="utf-8")
    code, out, err = server.run("--check", server.target)
    assert code == 0, err
    assert "rollback point" in out
    assert "BACKGROUND_WORKERS" not in out


def test_check_refuses_an_unknown_commit(server):
    code, _, err = server.run("--check", "0123456789abcdef0123456789abcdef01234567")
    assert code == 1
    assert "not a commit" in err


def test_check_refuses_a_commit_that_exists_only_on_the_server(server):
    # A commit made on the server (never pushed) is in the local repository but on no origin branch.
    local = git(server.app, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "made on the server")
    code, out, err = server.run("--check", local)
    assert code == 1
    assert "not on any origin branch" in err
    assert "rollback point" not in out


def test_check_refuses_a_commit_whose_only_origin_branch_was_deleted(server):
    # The server still remembers origin/gone, but the branch no longer exists on origin.
    local = git(server.app, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "on a deleted branch")
    git(server.app, "update-ref", "refs/remotes/origin/gone", local)
    code, out, err = server.run("--check", local)
    assert code == 1
    assert "not on any origin branch" in err
    assert "rollback point" not in out


def test_check_refuses_when_the_app_filesystem_is_short_of_space(server):
    server.flag("app-free-kib", "10")
    code, out, err = server.run("--check", server.target)
    assert code == 1
    assert f"not enough free space in {server.app.as_posix()}" in err
    assert "rollback point" not in out


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
    assert (backup / "pip-freeze.txt").read_text(encoding="utf-8") == "fastapi==0.1\n"
    if os.name == "posix":
        # Windows reports no real modes. The backup holds user data and is root-only.
        assert backup.stat().st_mode & 0o777 == 0o700
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
    # --all includes pip itself, so a pip upgrade is undone too.
    assert first(calls, "systemctl stop shieldbot") < first(calls, "pip freeze --all") < checkout
    assert checkout < first(calls, "pip install") < first(calls, "systemctl start shieldbot")
    assert first(calls, "systemctl start shieldbot") < first(calls, "curl")
    assert first(calls, "curl") < first(calls, "systemctl start shieldbot-bot")
    # Readiness is polled once the health checks pass, before the bot starts.
    ready = first(calls, "curl -sf --max-time 5 http://127.0.0.1:8000/api/ready")
    assert first(calls, "curl -sf --max-time 10 http://127.0.0.1:8000/api/health") < ready
    assert ready < first(calls, "systemctl start shieldbot-bot")
    assert server.active() == UNITS


def test_cutover_is_idempotent(server):
    assert server.run("--cutover", server.target)[0] == 0
    # Each cutover backs up into a directory named to the second; a fast machine finishes both in one second.
    time.sleep(1 - time.time() % 1)
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
    # The failing line and command are named.
    assert "failed at line" in err and "chain_info.py" in err
    assert "rolled back" in err
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.active() == UNITS
    assert not (server.app / "NEW_SCHEMA").exists()
    # The packages go back to the versions frozen before the deploy.
    [backup] = server.backups()
    assert f"pip install -q -r {backup.as_posix()}/pip-freeze.txt" in server.calls()


def assert_rolled_back(server, code, err):
    assert code == 1
    assert "rolled back" in err and "did not complete" not in err
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.active() == UNITS


def test_cutover_rolls_back_when_pip_fails(server):
    server.flag("pip-fails")
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    # The API never started on the target: the only starts are the restore's.
    starts = [call for call in server.calls() if call.startswith("systemctl start")]
    assert starts == ["systemctl start shieldbot", "systemctl start shieldbot-bot"]


def test_cutover_rolls_back_when_the_api_never_answers(server):
    server.flag("unhealthy-on-target")
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    assert "journalctl -u shieldbot -n 40 --no-pager" in server.calls()
    assert (
        "systemctl start shieldbot-bot" not in server.calls()[: first(server.calls(), "journalctl")]
    )


def test_cutover_rolls_back_when_the_api_never_becomes_ready(server):
    server.flag("unready")
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    calls = server.calls()
    assert len([call for call in calls if call.endswith("/api/ready")]) == 30
    assert "journalctl -u shieldbot -n 40 --no-pager" in calls
    assert "systemctl start shieldbot-bot" not in calls[: first(calls, "journalctl")]


def test_rollback_discards_edits_the_failed_run_made_to_tracked_files(server):
    # The failed run edits a file that only the target commit tracks; a plain checkout of the old commit refuses.
    server.flag("pip-dirties-tree")
    server.flag("pip-fails")
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    assert not (server.app / "NEW_SCHEMA").exists()
    assert git(server.app, "status", "--porcelain", "--untracked-files=no") == ""


def test_a_truncated_package_list_is_never_restored(server):
    # pip freeze dies half way: the partial list must not be what the restore installs from.
    server.flag("freeze-truncated")
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    [backup] = server.backups()
    assert not (backup / "pip-freeze.txt").exists()
    installs = [call for call in server.calls() if call.startswith("pip install")]
    assert installs == [f"pip install -q -r {server.app.as_posix()}/requirements.txt"]


def test_a_failed_package_restore_is_named(server):
    server.flag("pip-fails")
    server.flag("pip-fails-on-restore")
    code, _, err = server.run("--cutover", server.target)
    assert code == 1
    assert f"packages not restored: the venv still holds {server.target[:7]}'s packages" in err
    assert "the rollback did not complete" in err
    assert server.head() == server.old


def test_ctrl_c_during_cutover_rolls_back(server):
    # Ctrl-C signals the whole foreground process group: the script and the pip it is waiting for, which dies.
    server.flag("ctrl-c-during-pip")
    code, _, err = server.run("--cutover", server.target)
    assert "interrupted by SIGINT" in err
    assert_rolled_back(server, code, err)


@pytest.mark.parametrize("signal", ["HUP", "TERM", "INT", "QUIT"])
def test_a_signal_during_cutover_rolls_back(server, signal):
    # A dropped SSH session sends HUP. The same signal is sent again during the restore's own pip install, and
    # the restore must finish regardless.
    server.flag("signal-during-pip", signal)
    code, _, err = server.run("--cutover", server.target)
    assert f"interrupted by SIG{signal}" in err
    assert_rolled_back(server, code, err)
    assert len([call for call in server.calls() if call.startswith("pip install")]) == 2


@pytest.mark.parametrize("signal", ["HUP", "TERM", "QUIT"])
def test_a_signal_during_the_restore_does_not_cut_it_short(server, signal):
    # The deploy fails on its own, then the session drops while the restore reinstalls the old packages.
    server.flag("pip-fails")
    server.flag("signal-during-restore-pip", signal)
    code, _, err = server.run("--cutover", server.target)
    assert_rolled_back(server, code, err)
    # The signal is ignored: it neither starts a second restore nor ends this one.
    assert err.count("== Restoring") == 1
    assert "interrupted" not in err


def test_a_bot_holding_the_key_after_cutover_is_stopped_without_a_rollback(server):
    secret = "0x" + "5e" * 32
    environ = server.tmp / "proc" / "4343" / "environ"
    environ.parent.mkdir(parents=True)
    environ.write_bytes(f"PATH=/usr/bin\x00{KEY}={secret}\x00".encode())
    server.flag("next-pid-shieldbot-bot", "4343")
    code, out, err = server.run("--cutover", server.target)
    assert code == 1
    assert "SECURITY" in err
    assert secret not in out + err
    assert server.active() == {"shieldbot"}
    assert server.head() == server.target
    assert len([call for call in server.calls() if " checkout " in call]) == 1
    assert "rolled back" not in err


def test_a_rollback_that_cannot_bring_the_api_back_says_so(server):
    server.flag("unhealthy")
    code, _, err = server.run("--cutover", server.target)
    assert code == 1
    assert "the rollback did not complete" in err
    [backup] = server.backups()
    assert backup.as_posix() in err
    assert server.head() == server.old
    assert rows(server.db) == [1]


def test_manual_rollback_restores_the_saved_commit_and_database(server):
    assert server.run("--cutover", server.target)[0] == 0
    [backup] = server.backups()
    code, out, err = server.run("--rollback", backup.as_posix())
    assert code == 0, err + out
    assert server.head() == server.old
    assert rows(server.db) == [1]
    assert server.active() == UNITS


def test_manual_rollback_lists_the_hand_edits_it_discards(server):
    assert server.run("--cutover", server.target)[0] == 0
    (server.app / "requirements.txt").write_text(
        "fastapi\nhotfix-on-the-server\n", encoding="utf-8"
    )
    [backup] = server.backups()
    code, out, err = server.run("--rollback", backup.as_posix())
    assert code == 0, err + out
    assert "discarding edits to tracked files" in err
    assert " M requirements.txt" in err
    assert (server.app / "requirements.txt").read_text(encoding="utf-8") == "fastapi\n"


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
    code, _, err = backup.run(KEEP_DAYS="3", KEEP_COUNT="1")
    assert code == 0, err
    names = {path.name for path in backup.dir.iterdir()}
    assert "shieldbot_old.db" not in names
    assert {"shieldbot_recent.db", "unrelated.db"} <= names
    assert len([name for name in names if name.startswith("shieldbot_")]) == 2


def test_backup_keeps_the_newest_copies_after_a_long_outage(backup):
    # After weeks without a backup every older copy is past KEEP_DAYS; the newest KEEP_COUNT still stay.
    sqlite3.connect(backup.db).close()
    backup.dir.mkdir()
    now = time.time()
    for days in range(30, 35):
        path = backup.dir / f"shieldbot_{days}.db"
        path.write_bytes(b"")
        os.utime(path, (now - days * 86400, now - days * 86400))
    code, _, err = backup.run(KEEP_DAYS="7", KEEP_COUNT="3")
    assert code == 0, err
    names = sorted(path.name for path in backup.dir.iterdir())
    assert len(names) == 3
    assert {"shieldbot_30.db", "shieldbot_31.db"} <= set(names)


def test_backup_copies_off_box_only_when_asked(backup):
    sqlite3.connect(backup.db).close()
    code, out, err = backup.run(BACKUP_REMOTE="backup@example.net:/srv/shieldbot/")
    assert code == 0, err
    [copy] = backup.dir.glob("shieldbot_*.db")
    [call] = backup.calls()
    assert call.startswith("scp ") and call.endswith(
        f" -- {copy.as_posix()} backup@example.net:/srv/shieldbot/"
    )
    assert "BatchMode=yes" in call and "StrictHostKeyChecking=yes" in call


def test_a_copy_that_vanishes_while_pruning_does_not_stop_the_off_box_copy(backup):
    sqlite3.connect(backup.db).close()
    backup.dir.mkdir()
    old = backup.dir / "shieldbot_old.db"
    old.write_bytes(b"")
    os.utime(old, (time.time() - 30 * 86400, time.time() - 30 * 86400))
    (backup.state / "copies-vanish").write_bytes(b"")
    code, _, err = backup.run(
        KEEP_DAYS="7", KEEP_COUNT="1", BACKUP_REMOTE="backup@example.net:/srv/shieldbot/"
    )
    assert code == 0, err
    assert "could not prune" in err
    assert [call for call in backup.calls() if call.startswith("scp ")]


def test_a_failed_off_box_copy_fails_the_job_and_keeps_the_local_copy(backup):
    sqlite3.connect(backup.db).close()
    (backup.state / "scp-fails").write_bytes(b"")
    code, out, _ = backup.run(BACKUP_REMOTE="backup@example.net:/srv/shieldbot/")
    assert code != 0
    [copy] = backup.dir.glob("shieldbot_*.db")
    assert "Backup saved" in out and "Copied off-box" not in out


def test_backup_never_creates_a_missing_database(backup):
    code, _, err = backup.run()
    assert code != 0
    assert not backup.db.exists()
    assert not list(backup.dir.glob("shieldbot_*"))


@pytest.mark.parametrize("name", ["KEEP_DAYS", "KEEP_COUNT"])
@pytest.mark.parametrize("value", ["0", "7d", "-1"])
def test_backup_rejects_a_bad_retention_setting(backup, name, value):
    sqlite3.connect(backup.db).close()
    code, _, err = backup.run(**{name: value})
    assert code == 2
    assert name in err
    assert not backup.dir.exists()
