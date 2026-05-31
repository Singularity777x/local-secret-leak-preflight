from secret_preflight.cli import main


def test_main_placeholder(capsys):
    assert main([]) == 0
    assert "not implemented" in capsys.readouterr().out
