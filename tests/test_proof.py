import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import checks, evaluate

def test_readme_matches_output():
    readme = (pathlib.Path(__file__).parent.parent / "README.md").read_text()
    assert evaluate.results() in readme, "README results table drifted from evaluate.py"

def test_mutant_disabled_check_is_caught(monkeypatch):
    real = evaluate.results()
    monkeypatch.setattr(evaluate, "check", lambda text: True)
    assert evaluate.results() != real, "disabling the core check did not change the result"
