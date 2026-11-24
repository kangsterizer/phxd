"""Tests for YAML configuration overrides (``shared.HLConfig``)."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from shared.HLConfig import ConfigError, applyOverrides, loadOverrides
from tests.irc_harness import irc_server  # noqa: F401  (fixture)


def defaults():
    """A config.py-like namespace."""
    return {
        "os": os,
        "DB_FILE_BASEPATH": "textdb",
        "DB_FILE_NEWSDIR": os.path.join("textdb", "db_news"),
        "DB_FILE_ACCOUNTS": os.path.join("textdb", "db_accounts.txt"),
        "DB_FILE_LOG": os.path.join("textdb", "db_log.txt"),
        "DB_FILE_BANLIST": os.path.join("textdb", "db_banlist.txt"),
        "LOG_FILE": os.path.join("textdb", "phxd.log"),
        "LOG_LEVEL": "INFO",
        "ENABLE_FILE_LOG": True,
        "SERVER_PORT": 5500,
        "SERVER_NAME": "phxd server",
        "TRACKER_LIST": [],
        "IDLE_TIME": 600,
        "LINK_PORT": 5503,
    }


@pytest.fixture
def yaml_file(tmp_path):
    def write(text):
        path = tmp_path / "phxd.yaml"
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return str(path)

    return write


class TestApplyOverrides:
    def test_missing_file_changes_nothing(self, tmp_path):
        config = defaults()
        assert applyOverrides(config, str(tmp_path / "nope.yaml")) == []
        assert config == defaults()

    def test_empty_file_changes_nothing(self, yaml_file):
        config = defaults()
        assert applyOverrides(config, yaml_file("")) == []

    def test_overrides_values_with_case_insensitive_keys(self, yaml_file):
        config = defaults()
        changed = applyOverrides(
            config,
            yaml_file(
                """
                server_name: "Chatonly.org"
                SERVER_PORT: 5600
                enable_file_log: false
                """
            ),
        )
        assert sorted(changed) == ["ENABLE_FILE_LOG", "SERVER_NAME", "SERVER_PORT"]
        assert config["SERVER_NAME"] == "Chatonly.org"
        assert config["SERVER_PORT"] == 5600
        assert config["ENABLE_FILE_LOG"] is False

    def test_unicode_strings(self, yaml_file):
        config = defaults()
        applyOverrides(config, yaml_file('server_name: "Café Hotline"\n'))
        assert config["SERVER_NAME"] == "Café Hotline"

    def test_unknown_setting_is_an_error(self, yaml_file):
        with pytest.raises(ConfigError, match="unknown setting 'sever_name'"):
            applyOverrides(defaults(), yaml_file("sever_name: typo\n"))

    @pytest.mark.parametrize("name", ["os", "_private"])
    def test_non_settings_cannot_be_overridden(self, yaml_file, name):
        with pytest.raises(ConfigError, match="unknown setting"):
            applyOverrides(defaults(), yaml_file(f"{name}: 1\n"))

    @pytest.mark.parametrize(
        "text, message",
        [
            ("server_port: '5500'\n", "server_port must be a whole number"),
            ("server_port: true\n", "server_port must be a whole number"),
            ("enable_file_log: 1\n", "enable_file_log must be true or false"),
            ("server_name: 42\n", "server_name must be a string"),
            ("log_level: LOUD\n", "log_level must be one of"),
        ],
    )
    def test_wrong_types_are_errors(self, yaml_file, text, message):
        with pytest.raises(ConfigError, match=message):
            applyOverrides(defaults(), yaml_file(text))

    def test_log_level_is_normalised(self, yaml_file):
        config = defaults()
        applyOverrides(config, yaml_file("log_level: debug\n"))
        assert config["LOG_LEVEL"] == "DEBUG"

    def test_tracker_list_formats(self, yaml_file):
        config = defaults()
        applyOverrides(
            config,
            yaml_file(
                """
                tracker_list:
                  - tracker.preterhuman.net:5499
                  - hotline.ubersoft.org
                  - [tracked.nailbat.com, 5500]
                  - {host: hotline.duckdns.org, port: 5501}
                  - {host: example.org}
                """
            ),
        )
        assert config["TRACKER_LIST"] == [
            ("tracker.preterhuman.net", 5499),
            ("hotline.ubersoft.org", 5499),
            ("tracked.nailbat.com", 5500),
            ("hotline.duckdns.org", 5501),
            ("example.org", 5499),
        ]

    @pytest.mark.parametrize(
        "text",
        [
            "tracker_list: tracker.example\n",
            "tracker_list: [42]\n",
            "tracker_list: ['host:notaport']\n",
            "tracker_list: [':5499']\n",
        ],
    )
    def test_invalid_tracker_list(self, yaml_file, text):
        with pytest.raises(ConfigError):
            applyOverrides(defaults(), yaml_file(text))

    def test_derived_paths_follow_overridden_base(self, yaml_file):
        config = defaults()
        applyOverrides(config, yaml_file("db_file_basepath: /data\nserver_port: 6000\n"))
        assert config["DB_FILE_ACCOUNTS"] == os.path.join("/data", "db_accounts.txt")
        assert config["DB_FILE_NEWSDIR"] == os.path.join("/data", "db_news")
        assert config["LOG_FILE"] == os.path.join("/data", "phxd.log")
        assert config["LINK_PORT"] == 6003

    def test_explicit_derived_value_wins(self, yaml_file):
        config = defaults()
        applyOverrides(config, yaml_file("db_file_basepath: /data\nlog_file: /var/log/phxd.log\n"))
        assert config["LOG_FILE"] == "/var/log/phxd.log"
        assert config["DB_FILE_ACCOUNTS"] == os.path.join("/data", "db_accounts.txt")

    def test_derived_values_untouched_when_base_not_overridden(self, yaml_file):
        config = defaults()
        config["LOG_FILE"] = "/custom/from/config.py.log"
        applyOverrides(config, yaml_file("server_name: x\n"))
        assert config["LOG_FILE"] == "/custom/from/config.py.log"

    @pytest.mark.parametrize("text", ["- a\n- b\n", "server_name: [unclosed\n"])
    def test_malformed_file(self, yaml_file, text):
        with pytest.raises(ConfigError):
            applyOverrides(defaults(), yaml_file(text))


class TestLoadOverrides:
    def test_uses_phxd_config_env_var(self, yaml_file, tmp_path, monkeypatch):
        monkeypatch.setenv("PHXD_CONFIG", yaml_file("server_name: from env\n"))
        config = defaults()
        loadOverrides(config, str(tmp_path / "elsewhere"))
        assert config["SERVER_NAME"] == "from env"

    def test_defaults_to_phxd_yaml_next_to_config(self, yaml_file, tmp_path, monkeypatch):
        monkeypatch.delenv("PHXD_CONFIG", raising=False)
        yaml_file("server_name: beside config\n")
        config = defaults()
        loadOverrides(config, str(tmp_path))
        assert config["SERVER_NAME"] == "beside config"

    def test_errors_exit_with_readable_message(self, yaml_file, tmp_path, monkeypatch):
        monkeypatch.setenv("PHXD_CONFIG", yaml_file("bogus: 1\n"))
        with pytest.raises(SystemExit, match="phxd: configuration error: unknown setting"):
            loadOverrides(defaults(), str(tmp_path))


def test_real_config_module_applies_overrides(yaml_file, tmp_path):
    """Imports the real config.py in a fresh interpreter, like phxd does."""
    path = yaml_file(
        """
        server_name: "Chatonly.org"
        tracker_list: [tracker.preterhuman.net]
        db_file_basepath: /data
        irc_guest_login_delay: 0
        """
    )
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (
        "import config; "
        "print(config.SERVER_NAME, config.TRACKER_LIST, config.LOG_FILE, "
        "config.IRC_GUEST_LOGIN_DELAY, config.LOG_LEVEL, sorted(config.CONFIG_OVERRIDDEN))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo_root,
        env={**os.environ, "PHXD_CONFIG": path},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == (
        "Chatonly.org [('tracker.preterhuman.net', 5499)] /data/phxd.log 0 INFO "
        "['DB_FILE_BASEPATH', 'IRC_GUEST_LOGIN_DELAY', 'SERVER_NAME', 'TRACKER_LIST']"
    )


def test_server_logs_to_stdout_at_configured_level(irc_server):
    """docker logs shows INFO and up by default, not DEBUG packet dumps."""
    import logging
    import sys

    stdout_handlers = [
        h for h in irc_server.server.log.handlers
        if isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stdout
    ]
    assert stdout_handlers, "server should always log to stdout for docker logs"
    assert all(h.level == logging.INFO for h in stdout_handlers)


def test_example_file_is_valid():
    """phxd.yaml.example must load against the real config.py defaults."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    example = os.path.join(repo_root, "phxd.yaml.example")
    result = subprocess.run(
        [sys.executable, "-c", "import config; print(sorted(config.CONFIG_OVERRIDDEN))"],
        cwd=repo_root,
        env={**os.environ, "PHXD_CONFIG": example},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == (
        "['LOG_LEVEL', 'SERVER_DESCRIPTION', 'SERVER_NAME', 'TRACKER_LIST']"
    )


def test_twisted_messages_only_shown_when_debugging(irc_server):
    """Twisted's own chatter (several lines per tracker update) is logged
    at DEBUG; its errors stay at ERROR so they show up in docker logs."""
    import logging

    from twisted.python import log as twisted_log

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    capture = Capture(level=logging.DEBUG)
    twisted_logger = logging.getLogger("twisted")
    twisted_logger.addHandler(capture)
    try:
        twisted_log.msg("Starting protocol <HLTrackerClient>")
        twisted_log.err(RuntimeError("boom"), "something broke")
    finally:
        twisted_logger.removeHandler(capture)
    levels = {r.getMessage().split("\n")[0]: r.levelno for r in records}
    assert levels["Starting protocol <HLTrackerClient>"] == logging.DEBUG
    assert any(level == logging.ERROR and "something broke" in msg for msg, level in levels.items())
