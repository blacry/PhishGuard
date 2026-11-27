import pytest

import main


@pytest.mark.parametrize("interruption", [EOFError, KeyboardInterrupt])
def test_menu_exits_cleanly_when_input_ends_or_is_interrupted(
    monkeypatch, capsys, interruption
):
    def interrupt_input(_prompt):
        raise interruption

    monkeypatch.setattr("builtins.input", interrupt_input)

    main.main()

    assert "Input ended or interrupted. Exiting PhishGuard." in capsys.readouterr().out


def test_invalid_menu_choice_returns_retry_sentinel(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "not a number")

    assert main.get_user_choice() == -1


@pytest.mark.parametrize("interruption", [EOFError, KeyboardInterrupt])
def test_interrupted_delete_prompt_never_deletes_history(
    monkeypatch, capsys, interruption
):
    def interrupt_input(_prompt):
        raise interruption

    monkeypatch.setattr("builtins.input", interrupt_input)
    monkeypatch.setattr(
        main,
        "delete_scan_history",
        lambda: pytest.fail("history deletion must require explicit confirmation"),
    )

    main.handle_delete_history()

    assert "Scan history was not deleted." in capsys.readouterr().out


def test_interrupted_url_prompt_cancels_before_validation(monkeypatch, capsys):
    def interrupt_input(_prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt_input)
    monkeypatch.setattr(
        main, "is_valid_url", lambda _url: pytest.fail("canceled input was validated")
    )

    main.handle_url_scan()

    assert "URL scan canceled." in capsys.readouterr().out
