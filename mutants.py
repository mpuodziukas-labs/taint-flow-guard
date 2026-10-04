"""Mutation check: remove each defense in a scratch copy, the matching tests must go RED.
A control copy must pass first. A mutant that hangs past 8 s counts as killed."""
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).parent
T = "tests/test_guard.py"
H = "tests/test_review.py"  # hostile review findings T1-T11
# (name, file, text to remove, text to put in, test file that must fail)
MUTANTS = [
    ("slice: drop propagation, result looks owner-typed", "taintflow.py", "return t[0][p[0]:p[1]], args[0][1]", "return t[0][p[0]:p[1]], frozenset({TRUSTED})", T),
    ("upper: drop propagation", "taintflow.py", "return t[0].upper(), args[0][1]", "return t[0].upper(), frozenset({TRUSTED})", T),
    ("concat: keep only the first operand's labels", "taintflow.py", 'return "".join(t), _union(args)', 'return "".join(t), args[0][1]', T),
    ("format: drop propagation", "taintflow.py", "return p[0].format(*t), (_union(args) | {TEMPLATE} if lit else _union(args))", "return p[0].format(*t), frozenset({TRUSTED})", T),
    ("json: dumps drops propagation", "taintflow.py", "return json.dumps({\"v\": t[0]}), args[0][1]", "return json.dumps({\"v\": t[0]}), frozenset({TRUSTED})", T),
    ("json: loads drops propagation", "taintflow.py", "return json.loads(t[0])[\"v\"], args[0][1]", "return json.loads(t[0])[\"v\"], frozenset({TRUSTED})", T),
    ("unknown tool: skipped, not blocked", "taintflow.py", 'add("BLOCK", i, tool, None, None, "unknown tool")', "pass", T),
    ("unknown arg: skipped, not blocked", "taintflow.py", 'add("BLOCK", i, tool, arg, None, "argument not declared in policy")', "pass", T),
    ("unlabeled value: skipped, not blocked", "taintflow.py", 'add("BLOCK", i, tool, arg, None, "unlabeled or unknown value")', "pass", T),
    ("labels: a missing label list defaults to owner", "taintflow.py", 'spec.get("labels")', 'spec.get("labels", [TRUSTED])', T),
    ("sensitive arg: untrusted source never blocks", "taintflow.py", "                if hard:", "                if False:", T),
    ("ask: needs no owner, counts as allow", "taintflow.py", "                elif bad:", "                elif False:", T),
    ("tool choice: untrusted value may pick the tool", "taintflow.py", "            if bad:\n                add(\"BLOCK\", i, v[0]", "            if False:\n                add(\"BLOCK\", i, v[0]", T),
    ("empty plan: allowed", "taintflow.py", "    if not plan[\"calls\"]:", "    if False:", T),
    ("internal error: allowed", "taintflow.py", 'return "BLOCK", [{"severity"', 'return "ALLOW", [{"severity"', T),
    ("verdict: ask outranks block", "taintflow.py", '"BLOCK": 2}', '"BLOCK": 0}', T),
    ("record: free-arg labels not recorded", "taintflow.py", 'recorded.append({"call": i, "tool": tool, "arg": arg, "labels": sorted(v[1])})', "pass", T),
    ("cli: an unreadable file exits 0", "taintflow.py", "        return 2\n    verdict", "        return 0\n    verdict", T),
    ("duplicate JSON key: accepted, last one wins", "taintflow.py", 'raise Bad(f"duplicate key {k!r}")', "pass", H),
    ("sensitive arg missing from a call: not blocked", "taintflow.py", 'add("BLOCK", i, tool, arg, None, "sensitive argument missing from the call")', "pass", H),
    ("policy optional list ignored", "taintflow.py", 'arg not in spec.get("optional", [])', "arg not in []", H),
    ("ref with extra keys: accepted", "taintflow.py", '_keys(r, "ref", ("ref",))', "pass", H),
    ("call with extra keys: accepted", "taintflow.py", '_keys(c, f"call {i}", ("tool", "args"))', "pass", H),
    ("derived value with text or labels: accepted", "taintflow.py", '_keys(spec, f"value {vid}", ("op", "args"), ("params",))', "pass", H),
    ("format template text: counted as owner-typed", "taintflow.py", "lit = lit or bool(text)", "lit = False", H),
    ("output size cap: removed", "taintflow.py", 'if not isinstance(text, str) or len(text) > MAX_TEXT:', "if False:", H),
]


def pytest_rc(tree, test):
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                           cwd=tree, capture_output=True, timeout=8,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124                                      # a mutant that hangs the tests is caught
    return r.returncode


def fresh(tmp, name):
    dst = pathlib.Path(tmp) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dst


def main():
    killed = 0
    tests = sorted({m[4] for m in MUTANTS})
    with tempfile.TemporaryDirectory() as tmp:
        for t in tests:
            if pytest_rc(fresh(tmp, "control-" + pathlib.Path(t).stem), t) != 0:
                print(f"control FAIL {t}"); return 1
        print(f"control {len(tests)}/{len(tests)} test files pass unmodified")
        for i, (name, f, old, new, test) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1"); return 1
            (tree / f).write_text(src.replace(old, new))
            red = pytest_rc(tree, test) != 0
            killed += red
            print(f"{'RED ' if red else 'LIVE'} {name}")
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
