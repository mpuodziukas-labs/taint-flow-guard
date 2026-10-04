import json, pathlib
from checks import check

def results():
    rows = [json.loads(l) for l in pathlib.Path(__file__).with_name("cases.jsonl").read_text().splitlines() if l]
    caught = sum(1 for r in rows if r["bad"] and not check(r["text"]))
    passed = sum(1 for r in rows if not r["bad"] and check(r["text"]))
    bad = sum(r["bad"] for r in rows)
    return f"| bad caught | good passed |\n|---|---|\n| {caught}/{bad} | {passed}/{len(rows) - bad} |"

if __name__ == "__main__":
    print(results())
