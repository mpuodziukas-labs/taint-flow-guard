"""Run every planted plan through the flow guard, and the five injection wordings through the flow guard and a pattern scanner.
Prints two tables. Exit 1 if any verdict or named finding is wrong."""
import json, pathlib, sys
from taintflow import check
from baseline_scanner import scan_input

HERE = pathlib.Path(__file__).parent
FIX = HERE / "tests" / "fixtures"
POLICY = (FIX / "policy.json").read_text()


def rows():
    """(class, id, ok) per line of cases.jsonl."""
    out = []
    for raw in (HERE / "cases.jsonl").read_text().splitlines():
        c = json.loads(raw)
        verdict, found, _ = check((FIX / f"{c['file']}.json").read_text(), POLICY)
        hit = lambda f: all(c[k] is None or f[k] == c[k] for k in ("call", "arg", "source"))
        ok = verdict == c["expect"] and (c["expect"] == "ALLOW" or any(hit(f) for f in found))
        out.append((c["class"], c["id"], ok))
    return out


def results():
    tally = {}
    for cls, _, ok in rows():
        a = tally.setdefault(cls, [0, 0]); a[0] += ok; a[1] += 1
    return "\n".join(["| class | verdict and named finding as labeled |", "|---|---|"] + [f"| {k} | {a}/{b} |" for k, (a, b) in tally.items()])


def wording_rows():
    out = []
    for n in ("classic_english", "paraphrase", "spanish", "german", "polite_cover_story"):
        text = (FIX / f"exfil_{n}.json").read_text()
        page = json.loads(text)["values"]["page"]["text"]
        out.append({"wording": n, "flow": check(text, POLICY)[0], "scanner": scan_input(page.encode(), n)["verdict"]})
    return out


def side_by_side():
    return "\n".join(["| wording of the same attack | pattern scanner | flow guard |", "|---|---|---|"] +
                     [f"| {r['wording']} | {r['scanner']} | {r['flow']} |" for r in wording_rows()])


if __name__ == "__main__":
    print(results())
    print()
    print(side_by_side())
    sys.exit(0 if rows() and all(ok for *_, ok in rows()) else 1)
