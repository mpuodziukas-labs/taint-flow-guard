"""Taint-flow guard: untrusted data may not choose a tool or reach a sensitive tool argument, whatever it says.
Values carry labels: "trusted-owner" or "untrusted:<source>". Labels propagate through every derivation.
Plan: {"values": {id: {"text", "labels"} | {"op", "args": [{"ref"}], "params"}}, "calls": [{"tool", "args": {name: {"ref"}}}]}.
Policy: {"tools": {tool: {"sensitive": {arg: {"allow": [label], "ask": [label]}}, "free": [arg]}}}.
Verdict ALLOW, ASK_OWNER or BLOCK. Fail closed: any doubt, any error is BLOCK."""
import json, sys

TRUSTED = "trusted-owner"
RANK = {"ALLOW": 0, "ASK_OWNER": 1, "BLOCK": 2}


class Bad(Exception):
    pass


def _labels(ls):
    if not isinstance(ls, list) or not ls:
        raise Bad("value has no labels")
    for x in ls:
        if not isinstance(x, str) or not (x == TRUSTED or (x.startswith("untrusted:") and len(x) > 10)):
            raise Bad(f"invalid label {x!r}")
    return frozenset(ls)


def _union(args):
    return frozenset().union(*(a[1] for a in args))


def _apply(op, args, p):
    """args: [(text, labels)]. Returns (text, labels). The labels line of each op is its propagation rule."""
    t = [a[0] for a in args]
    if op == "slice":
        return t[0][p[0]:p[1]], args[0][1]
    if op == "upper":
        return t[0].upper(), args[0][1]
    if op == "concat":
        return "".join(t), _union(args)
    if op == "format":
        return p[0].format(*t), _union(args)
    if op == "json_dumps":
        return json.dumps({"v": t[0]}), args[0][1]
    if op == "json_loads":
        return json.loads(t[0])["v"], args[0][1]
    raise Bad(f"unknown op {op!r}")


def _policy(text):
    try:
        pol = json.loads(text)
    except ValueError:
        raise Bad("policy is not valid JSON")
    if not isinstance(pol, dict) or not isinstance(pol.get("tools"), dict) or not pol["tools"]:
        raise Bad("policy has no tools")
    for tool, spec in pol["tools"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("sensitive"), dict) or not isinstance(spec.get("free"), list):
            raise Bad(f"policy for {tool} needs sensitive and free")
        for arg, rule in spec["sensitive"].items():
            if not isinstance(rule, dict) or not isinstance(rule.get("allow"), list) or not isinstance(rule.get("ask"), list):
                raise Bad(f"policy for {tool}.{arg} needs allow and ask lists")
    return pol


def _check(plan_text, policy_text):
    pol = _policy(policy_text)
    try:
        plan = json.loads(plan_text)
    except ValueError:
        raise Bad("plan is not valid JSON")
    if not isinstance(plan, dict) or not isinstance(plan.get("values"), dict) or not isinstance(plan.get("calls"), list):
        raise Bad("plan needs values and calls")
    if not plan["calls"]:
        raise Bad("empty plan")
    vals = {}
    for vid, spec in plan["values"].items():
        if "op" in spec:
            refs = [vals.get(a.get("ref")) if isinstance(a, dict) else None for a in spec["args"]]
            if not refs or None in refs:
                raise Bad(f"value {vid} derives from an unknown value")
            vals[vid] = _apply(spec["op"], refs, spec.get("params", []))
        else:
            if not isinstance(spec["text"], str):
                raise Bad(f"value {vid} text is not a string")
            vals[vid] = (spec["text"], _labels(spec.get("labels")))
    found, recorded = [], []

    def add(sev, i, tool, arg, source, why):
        found.append({"severity": sev, "call": i, "tool": tool, "arg": arg, "source": source, "reason": why})

    def ref(r):
        return vals.get(r.get("ref")) if isinstance(r, dict) else None

    for i, c in enumerate(plan["calls"]):
        tool = c["tool"]
        if not isinstance(tool, str):
            v = ref(tool)
            if v is None:
                add("BLOCK", i, None, None, None, "tool comes from an unlabeled or unknown value")
                continue
            bad = sorted(x for x in v[1] if x != TRUSTED)
            if bad:
                add("BLOCK", i, v[0], None, bad[0], "an untrusted value chooses which tool runs")
                continue
            tool = v[0]
        spec = pol["tools"].get(tool)
        if spec is None:
            add("BLOCK", i, tool, None, None, "unknown tool")
            continue
        for arg, r in c["args"].items():
            v = ref(r)
            if v is None:
                add("BLOCK", i, tool, arg, None, "unlabeled or unknown value")
            elif arg in spec["sensitive"]:
                rule = spec["sensitive"][arg]
                bad = sorted(x for x in v[1] if x not in rule["allow"])
                hard = [x for x in bad if x not in rule["ask"]]
                if hard:
                    add("BLOCK", i, tool, arg, hard[0], "source may not reach this argument")
                elif bad:
                    add("ASK_OWNER", i, tool, arg, bad[0], "owner must approve this source for this argument")
            elif arg in spec["free"]:
                recorded.append({"call": i, "tool": tool, "arg": arg, "labels": sorted(v[1])})
            else:
                add("BLOCK", i, tool, arg, None, "argument not declared in policy")
    verdict = max((f["severity"] for f in found), key=RANK.get, default="ALLOW")
    return verdict, found, recorded


def check(plan_text, policy_text):
    """Return (verdict, findings, recorded). recorded lists the labels of every value in a non-sensitive arg."""
    try:
        return _check(plan_text, policy_text)
    except Exception as e:  # fail closed: an error is never an allow
        return "BLOCK", [{"severity": "BLOCK", "call": None, "tool": None, "arg": None, "source": None,
                          "reason": f"fail closed: {type(e).__name__}: {e}"}], []


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: python3 -m taintflow <policy.json> <plan.json>")
        return 2
    try:
        texts = [open(a, encoding="utf-8").read() for a in argv]
    except (OSError, UnicodeError) as e:
        print(f"cannot read input: {type(e).__name__}")
        return 2
    verdict, found, _ = check(texts[1], texts[0])
    print(verdict + "".join(f" | call {f['call']} {f['tool']}.{f['arg']} from {f['source']}: {f['reason']}" for f in found))
    return {"ALLOW": 0, "BLOCK": 1, "ASK_OWNER": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
