"""
Tests for manage_logs.py — log management UI.

Covers:
- parse_log_selection
- Change location: no-logs, same-path, move yes/no, cancel
- Extra directories: display, auto-cleanup, cross-dir delete
- All: deletes from all directories
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user_config(log_dir: str, extra_dirs: list[str] | None = None):
    """Minimal UserConfig stand-in backed by a plain dict."""
    store: dict[str, str] = {"log_dir": log_dir}
    if extra_dirs is not None:
        store["log_dirs_extra"] = json.dumps(extra_dirs)
    uc = MagicMock()
    uc.get.side_effect = lambda k: store.get(k)
    uc.set.side_effect = lambda k, v: store.update({k: v})
    return uc, store


def _make_config():
    return SimpleNamespace(no_color=True)


def _t(key, **kwargs):
    from ufw_audit.i18n import t
    return t(key, **kwargs)


def _make_log(directory: Path, name: str) -> Path:
    f = directory / name
    f.write_text("x")
    return f


# ---------------------------------------------------------------------------
# parse_log_selection
# ---------------------------------------------------------------------------

class TestParseLogSelection:
    def _parse(self, answer, max_idx):
        from ufw_audit.manage_logs import parse_log_selection
        return parse_log_selection(answer, max_idx)

    def test_single(self):
        assert self._parse("1", 3) == [1]

    def test_multiple_csv(self):
        assert self._parse("1,3", 3) == [1, 3]

    def test_range(self):
        assert self._parse("2-4", 5) == [2, 3, 4]

    def test_mixed(self):
        assert self._parse("1,3-5", 5) == [1, 3, 4, 5]

    def test_out_of_bounds_ignored(self):
        assert self._parse("9", 3) == []

    def test_invalid_string(self):
        assert self._parse("abc", 3) == []

    def test_empty(self):
        assert self._parse("", 3) == []


# ---------------------------------------------------------------------------
# _get_extra_dirs / _set_extra_dirs / _add_extra_dir
# ---------------------------------------------------------------------------

class TestExtraDirsHelpers:
    def test_get_empty(self, tmp_path):
        from ufw_audit.manage_logs import _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        assert _get_extra_dirs(uc) == []

    def test_get_returns_paths(self, tmp_path):
        from ufw_audit.manage_logs import _get_extra_dirs
        d1 = tmp_path / "a"
        d2 = tmp_path / "b"
        uc, _ = _make_user_config(str(tmp_path), extra_dirs=[str(d1), str(d2)])
        assert _get_extra_dirs(uc) == [d1, d2]

    def test_add_new(self, tmp_path):
        from ufw_audit.manage_logs import _add_extra_dir, _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        d = tmp_path / "extra"
        _add_extra_dir(uc, d)
        assert _get_extra_dirs(uc) == [d]

    def test_add_duplicate_ignored(self, tmp_path):
        from ufw_audit.manage_logs import _add_extra_dir, _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        d = tmp_path / "extra"
        _add_extra_dir(uc, d)
        _add_extra_dir(uc, d)
        assert _get_extra_dirs(uc) == [d]

    def test_invalid_json_returns_empty(self, tmp_path):
        from ufw_audit.manage_logs import _get_extra_dirs
        uc, store = _make_user_config(str(tmp_path))
        store["log_dirs_extra"] = "not-json"
        assert _get_extra_dirs(uc) == []


# ---------------------------------------------------------------------------
# Change location — no existing logs → no move prompt
# ---------------------------------------------------------------------------

class TestChangeLocationNoLogs:
    def test_no_logs_no_move_prompt(self, tmp_path):
        """Empty current dir: no move question, config updated."""
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)

    def test_same_path_no_move_prompt(self, tmp_path):
        """Choosing same path: no extras added, no move question."""
        old_dir = tmp_path / "logs"
        old_dir.mkdir()
        _make_log(old_dir, "ufw_audit_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[old_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(old_dir)
        assert (old_dir / "ufw_audit_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# Change location — move YES
# ---------------------------------------------------------------------------

class TestMoveLogsYes:
    def test_logs_moved_to_new_dir(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        log1 = _make_log(old_dir, "ufw_audit_2026-01-01.log")
        log2 = _make_log(old_dir, "ufw_audit_2026-01-02.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert (new_dir / "ufw_audit_2026-01-01.log").exists()
        assert (new_dir / "ufw_audit_2026-01-02.log").exists()
        assert not log1.exists()
        assert not log2.exists()

    def test_moved_count_in_output(self, tmp_path, capsys):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        for i in range(3):
            _make_log(old_dir, f"ufw_audit_2026-01-0{i+1}.log")

        uc, _ = _make_user_config(str(old_dir))
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert "3" in capsys.readouterr().out

    def test_move_includes_extra_dir_logs(self, tmp_path):
        """Logs from previous (extra) dirs are also moved when user says yes."""
        old_dir = tmp_path / "old"
        extra_dir = tmp_path / "extra"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        extra_dir.mkdir()
        _make_log(old_dir, "ufw_audit_2026-01-01.log")
        ex_log = _make_log(extra_dir, "ufw_audit_2026-01-02.log")

        uc, store = _make_user_config(str(old_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert (new_dir / "ufw_audit_2026-01-01.log").exists()
        assert (new_dir / "ufw_audit_2026-01-02.log").exists()
        assert not ex_log.exists()


# ---------------------------------------------------------------------------
# Change location — move NO
# ---------------------------------------------------------------------------

class TestMoveLogsNo:
    def test_logs_stay_in_old_dir(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        log = _make_log(old_dir, "ufw_audit_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "n", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert log.exists()
        assert not (new_dir / "ufw_audit_2026-01-01.log").exists()

    def test_old_dir_added_to_extras(self, tmp_path):
        """When user declines move, old dir is tracked in log_dirs_extra."""
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        _make_log(old_dir, "ufw_audit_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "n", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from ufw_audit.manage_logs import _get_extra_dirs
        assert old_dir in _get_extra_dirs(uc)

    def test_empty_answer_treated_as_no(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        _make_log(old_dir, "ufw_audit_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[new_dir]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert (old_dir / "ufw_audit_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# Extra directories: display and auto-cleanup
# ---------------------------------------------------------------------------

class TestExtraDirectoriesDisplay:
    def test_extra_logs_shown_in_output(self, tmp_path, capsys):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(extra_dir, "ufw_audit_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "ufw_audit_2026-01-01.log" in out
        assert str(extra_dir) in out

    def test_extra_dir_header_shown(self, tmp_path, capsys):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(extra_dir, "ufw_audit_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        # The ─── separator is hardcoded in the UI (not translated) and the
        # extra dir path always appears in the header line.
        assert "───" in out
        assert str(extra_dir) in out

    def test_empty_extra_dir_auto_removed(self, tmp_path):
        """Extra dir that is empty should be dropped from the list."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "empty_extra"
        cur_dir.mkdir()
        extra_dir.mkdir()  # exists but no logs

        uc, store = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from ufw_audit.manage_logs import _get_extra_dirs
        assert _get_extra_dirs(uc) == []

    def test_nonexistent_extra_dir_auto_removed(self, tmp_path):
        cur_dir = tmp_path / "current"
        cur_dir.mkdir()
        ghost = tmp_path / "ghost"  # does not exist

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(ghost)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from ufw_audit.manage_logs import _get_extra_dirs
        assert _get_extra_dirs(uc) == []

    def test_flat_index_spans_all_dirs(self, tmp_path):
        """Index numbers must be contiguous across current + extra dirs."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(cur_dir, "ufw_audit_2026-01-01.log")
        _make_log(cur_dir, "ufw_audit_2026-01-02.log")
        _make_log(extra_dir, "ufw_audit_2026-01-03.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs), \
             __import__("io").StringIO() as _:
            import io
            from unittest.mock import patch as _patch
            import ufw_audit.manage_logs as ml
            with _patch("builtins.print") as mock_print:
                with _patch("builtins.input", side_effect=["q"]):
                    ml.run_manage_logs(uc, _make_config(), _t)

            printed = " ".join(str(c) for c in mock_print.call_args_list)
            assert "[ 3]" in printed


# ---------------------------------------------------------------------------
# Delete by index from extra directory
# ---------------------------------------------------------------------------

class TestDeleteFromExtraDir:
    def test_delete_extra_dir_log_by_index(self, tmp_path):
        """A log in an extra dir can be deleted by its flat index."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(cur_dir, "ufw_audit_2026-01-01.log")
        ex_log = _make_log(extra_dir, "ufw_audit_2026-01-02.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        # Index 2 = first log in extra dir
        inputs = iter(["2", "q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert not ex_log.exists()
        assert (cur_dir / "ufw_audit_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# 'all' deletes from all directories
# ---------------------------------------------------------------------------

class TestDeleteAll:
    def test_all_deletes_across_dirs(self, tmp_path):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        cur_log = _make_log(cur_dir, "ufw_audit_2026-01-01.log")
        ex_log = _make_log(extra_dir, "ufw_audit_2026-01-02.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["all", "y", "q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert not cur_log.exists()
        assert not ex_log.exists()

    def test_all_cancel_leaves_files(self, tmp_path):
        cur_dir = tmp_path / "current"
        cur_dir.mkdir()
        log = _make_log(cur_dir, "ufw_audit_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir))
        inputs = iter(["all", "n", "q"])

        with patch("builtins.input", side_effect=inputs):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert log.exists()


# ---------------------------------------------------------------------------
# Change location — cancel
# ---------------------------------------------------------------------------

class TestChangeLocationCancel:
    def test_cancel_does_not_update_config(self, tmp_path):
        old_dir = tmp_path / "old"
        old_dir.mkdir()
        _make_log(old_dir, "ufw_audit_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("ufw_audit.manage_logs.prompt_path", side_effect=[None]):
            from ufw_audit.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(old_dir)
