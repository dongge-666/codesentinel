from codesentinel import __version__


def test_project_version_is_initialized() -> None:
    assert __version__ == "0.1.0"
