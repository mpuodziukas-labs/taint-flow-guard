import pathlib
import evaluate, mutants

README = (pathlib.Path(__file__).parent.parent / "README.md").read_text()


def test_every_case_gets_its_labeled_verdict_and_names():
    rows = evaluate.rows()
    assert len(rows) >= 20
    assert all(ok for *_, ok in rows)


def test_readme_tables_match_evaluate_output():
    assert evaluate.results() in README, "README flow-guard table drifted from evaluate.py"
    assert evaluate.side_by_side() in README, "README side-by-side table drifted from evaluate.py"


def test_the_scanner_column_is_real_not_constant():
    verdicts = {r["scanner"] for r in evaluate.wording_rows()}
    assert len(verdicts) >= 2, "the baseline scanner gave one verdict for every wording; the side-by-side proves nothing"
    assert {r["flow"] for r in evaluate.wording_rows()} == {"BLOCK"}


def test_readme_lists_every_mutant_and_the_count():
    for name, *_ in mutants.MUTANTS:
        assert f"RED  {name}" in README, f"README misses mutant: {name}"
    assert f"mutants killed {len(mutants.MUTANTS)}/{len(mutants.MUTANTS)}" in README


def test_every_mutant_pattern_exists_exactly_once():
    root = pathlib.Path(mutants.ROOT)
    for name, f, old, new, test in mutants.MUTANTS:
        assert (root / f).read_text().count(old) == 1, name
        assert (root / test).exists(), name


def test_each_required_defense_has_a_mutant():
    names = " ".join(m[0] for m in mutants.MUTANTS).lower()
    for word in ("slice", "format", "unknown tool", "concat", "json"):
        assert word in names, word
