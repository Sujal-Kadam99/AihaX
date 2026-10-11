import io
import logging

import pytest

from backend.core import logger as logger_module
from backend.core.logger import REDACTED, SensitiveDataFilter, redact_text


@pytest.mark.parametrize(
    "message, leaked",
    [
        ("primary_creds resolved to: {'username': 'a', 'password': 'hunter2'}", "hunter2"),
        ("cookies: {'sessionid': 'abc123'}", "abc123"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("login token=s3cr3t next", "s3cr3t"),
        ("request failed, using Bearer abc.def", "abc.def"),
        ("Authorization: token ghp_SECRET123", "ghp_SECRET123"),
        ('Authorization: Digest username="bob", response="deadbeef"', "deadbeef"),
        ("Cookie: session=abc; other=xyz", "xyz"),
        ("login password=my pass word", "pass word"),
        ('{"password": "ab\\"cd"}', 'cd"'),
        ("cookies: {\n'foo': 'abc'\n}", "abc"),
        ("GET /x?token=LEAK1&a=1", "LEAK1"),
    ],
)
def test_redact_text_masks_secrets(message, leaked):
    redacted = redact_text(message)
    assert leaked not in redacted
    assert REDACTED in redacted


def test_redact_text_leaves_plain_messages_alone():
    assert redact_text("campaign 42 started with 3 targets") == "campaign 42 started with 3 targets"


def test_filter_redacts_formatted_string_records():
    record = logging.LogRecord(
        "test", logging.INFO, "", 0, "creds: password=%s", ("hunter2",), None
    )
    SensitiveDataFilter().filter(record)
    assert "hunter2" not in record.getMessage()


def test_configure_logging_gives_module_loggers_a_handler(monkeypatch):
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    monkeypatch.setattr(logger_module, "_configured", False)
    try:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        logger_module.configure_logging()
        logger_module.configure_logging()  # idempotent
        assert len(root.handlers) == 1
        assert any(isinstance(f, SensitiveDataFilter) for f in root.handlers[0].filters)
        assert logging.getLogger("backend.services.campaign_worker").isEnabledFor(logging.INFO)
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)


def test_redact_text_keeps_key_suffix_and_unrelated_tail():
    assert redact_text("max_tokens=512") == f"max_tokens={REDACTED}"
    assert redact_text("api_key: [1, 2] campaign 42 started") == f"api_key: {REDACTED} campaign 42 started"


def _emit(configure, *args):
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SensitiveDataFilter())
    log = logging.Logger("test_logging_hygiene.emit", logging.DEBUG)  # detached: no pytest handlers
    log.addHandler(handler)
    configure(log, *args)
    return buf.getvalue()


def test_handler_output_redacts_exception_tracebacks():
    def run(log):
        try:
            raise ValueError("password=hunter2")
        except ValueError:
            log.exception("boom")

    out = _emit(run)
    assert "hunter2" not in out
    assert "boom" in out and "Traceback" in out


def test_handler_output_redacts_secrets_in_dicts_inside_lists():
    out = _emit(lambda log: log.info({"users": [{"password": "hunter2"}], "keyword": "kept", "api_key": "zzz"}))
    assert "hunter2" not in out and "zzz" not in out
    assert "kept" in out


def test_filter_never_raises_on_bad_format_args():
    out = _emit(lambda log: log.info("bad %s %s", "x"))
    assert "withheld" in out


def test_configure_logging_adds_filter_to_preexisting_handlers(monkeypatch):
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    monkeypatch.setattr(logger_module, "_configured", False)
    foreign = logging.StreamHandler(io.StringIO())
    try:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        root.addHandler(foreign)
        logger_module.configure_logging()
        assert any(isinstance(f, SensitiveDataFilter) for f in foreign.filters)
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        for noisy in logger_module._NOISY_LOGGERS:
            logging.getLogger(noisy).setLevel(logging.NOTSET)
