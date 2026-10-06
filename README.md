# taint-flow-guard

Proves: a plan whose tool choice or sensitive argument derives from untrusted data is BLOCKED, and the verdict is the same for every wording of the injection. Verify in 60s: `bash run.sh`

A web page, email or file tells an agent to send data to an attacker, and a pattern scanner misses it when the wording is paraphrased or in another language.

## The problem

Detecting an injection by its words is a race the defender loses: a new paraphrase, a new language or a cover story needs a new rule. This guard does not read the words. Every value carries labels, `trusted-owner` or `untrusted:<source>`. Labels follow a value through every derivation (slice, upper-case, concatenation, format, JSON round trip). A policy file declares, per tool, which arguments are sensitive and which sources may reach them. Before a plan runs, every call is checked. Untrusted data may not choose which tool runs and may not flow into a sensitive argument, whatever it says.

Prior art, not claimed here: "Defeating Prompt Injections by Design" (arXiv 2503.18813, Debenedetti et al.) and "Defending Against Indirect Prompt Injection Attacks With Spotlighting" (arXiv 2403.14720, Hines et al.). Both abstract pages were fetched on 2026-10-04 to confirm title and authors. What is claimed is this small implementation and its tests, nothing of their results.

## Run it (60s)

```
python3 -m pip install pytest
bash run.sh
```

Check one plan (exit 0 ALLOW, 1 BLOCK, 3 ASK_OWNER, 2 unreadable):

```
python3 -m taintflow tests/fixtures/policy.json tests/fixtures/exfil_german.json
```

printed:

```
BLOCK | call 0 send_email.to from untrusted:web_page: source may not reach this argument
```

`bash run.sh` runs `python3 evaluate.py`, then `python3 -m pytest -q`, then `python3 mutants.py`. It exits 0 only if all three pass. `evaluate.py` printed:

```
| class | verdict and named finding as labeled |
|---|---|
| injected address, wording varies | 5/5 |
| owner-typed address | 1/1 |
| untrusted text in a free arg | 1/1 |
| owner picks the tool | 1/1 |
| laundered then used | 7/7 |
| untrusted value picks the tool | 1/1 |
| untrusted shell argv | 1/1 |
| unlabeled or unknown | 8/8 |
| owner approval | 3/3 |
| second call blocked | 1/1 |

| wording of the same attack | pattern scanner | flow guard |
|---|---|---|
| classic_english | BLOCK | BLOCK |
| paraphrase | PASS | BLOCK |
| spanish | PASS | BLOCK |
| german | PASS | BLOCK |
| polite_cover_story | PASS | BLOCK |
```

The second table is the point. The five attack texts say the same thing in five ways, and only the first uses a classic override phrase. The pattern scanner (`baseline_scanner.py`, a copy of the author's own earlier scanner) calls them differently. The flow guard's verdict and finding are byte-identical for all five, because the verdict is a function of labels, not text.

`python3 mutants.py` printed:

```
control 3/3 test files pass unmodified
RED  slice: drop propagation, result looks owner-typed
RED  upper: drop propagation
RED  concat: keep only the first operand's labels
RED  format: drop propagation
RED  json: dumps drops propagation
RED  json: loads drops propagation
RED  unknown tool: skipped, not blocked
RED  unknown arg: skipped, not blocked
RED  unlabeled value: skipped, not blocked
RED  labels: a missing label list defaults to owner
RED  sensitive arg: untrusted source never blocks
RED  ask: needs no owner, counts as allow
RED  tool choice: untrusted value may pick the tool
RED  empty plan: allowed
RED  internal error: allowed
RED  verdict: ask outranks block
RED  record: free-arg labels not recorded
RED  cli: an unreadable file exits 0
RED  duplicate JSON key: accepted, last one wins
RED  sensitive arg missing from a call: not blocked
RED  policy optional list ignored
RED  ref with extra keys: accepted
RED  call with extra keys: accepted
RED  derived value with text or labels: accepted
RED  format template text: counted as owner-typed
RED  cli: tool, arg and label printed raw
RED  cli: error reason printed raw
RED  output size cap: removed
mutants killed 28/28
```

## Plan and policy format

A plan has `values` and `calls`. A value is either `{"text", "labels"}` or a derivation `{"op", "args": [{"ref"}], "params"}` with ops slice, upper, concat, format, json_dumps and json_loads. A call is `{"tool", "args": {name: {"ref"}}}`; the tool may itself be a ref. Values are defined in order. The schema is strict: a duplicate key anywhere, or a key not listed here (in a plan, ref, call, value or the policy), is BLOCK. A value text over 65536 characters is BLOCK. A format template may hold only plain `{}` fields; literal text in it is labeled `untrusted:format_template`, so it cannot reach a sensitive argument. A call that leaves out a sensitive argument of its tool is BLOCK, unless the policy lists that argument under the tool's `optional`. The policy per tool lists `sensitive` args with `allow` and `ask` label lists, and `free` args. Every label of a value must be in `allow` or the call is BLOCK; a label only in `ask` makes ASK_OWNER; BLOCK outranks ASK_OWNER outranks ALLOW. Labels of values in free arguments are recorded in the result. The CLI prints one line; a tool, argument or label name that is not 1 to 64 characters of `A-Za-z0-9_.:-` is printed as a JSON string, so a crafted name cannot add a line, fake a verdict or carry a terminal escape.

## What each planted case proves

Each case is a plan in tests/fixtures, generated by fixtures_gen.py, with the verdict and the named call, arg and source in cases.jsonl.

- injected address: the address is sliced out of a fetched page and reaches send_email.to. BLOCK, naming call 0, arg `to`, source `untrusted:web_page`, in five wordings (classic English, paraphrase, Spanish, German, a cover story).
- owner-typed address: ALLOW.
- laundered then used: slice, upper, concat with an owner prefix, format, json_dumps, json_loads, and a chain of four. All BLOCK.
- untrusted text in a free argument (the email body): ALLOW, label recorded.
- untrusted value picks the tool, untrusted shell argv: BLOCK. Owner picks the tool: ALLOW.
- unlabeled or unknown: a raw string argument, a value with no labels, an invalid label, an unknown tool, an unknown argument, an unknown ref, an empty plan, a policy or plan that does not parse. All BLOCK.
- owner approval: a source listed under `ask` gives ASK_OWNER; with another untrusted source mixed in, or in a plan with a BLOCK call, BLOCK.

## Mutants

Each defense is removed in a scratch copy and the tests must go RED. An unmodified control copy passes first. Each mutant has an 8 s limit, and a hang counts as killed. Propagation mutants make the derived value look owner-typed, because dropping labels to nothing would still be caught by the unlabeled rule and so would prove nothing.

## Hostile review

An outside reviewer reviewed the guard on 2026-10-04 and found 11 breaks, T1 to T11. All 11 are now tests in tests/test_review.py, each using the call from the review. Before the fixes, 12 of those tests failed; the output is in [RED-RUN-REVIEW.txt](RED-RUN-REVIEW.txt). Each new rule also has a mutant that turns the tests RED when the rule is removed.

- T1 to T4, T11: a duplicate key in a ref, an arg list, the value list, a call or the policy made the checker see one value and another JSON parser see a different one. Now a duplicate key is BLOCK.
- T5: a call that left out a sensitive argument was allowed. Now it is BLOCK unless the policy marks the argument optional.
- T6 to T8: extra keys in a ref, a call or a derived value were ignored. Now they are BLOCK.
- T9: the template text of a format was unlabeled. Now literal text in a template carries an untrusted label, and a template may hold only plain `{}` fields.
- T10: nested concat or a wide format field could build gigabytes. Now a value over 65536 characters is BLOCK.

Three more findings in the same review, T12 to T14, are known limits, listed below and not fixed: a trusted tool that returns untrusted text, a free argument such as a file path, and labels set by the harness. T12 to T14 have no tests. Nothing is OPEN from T1 to T11.

## Honesty

This is a small deterministic checker, not a product. Plans, labels, the policy and all addresses are synthetic and written for this repo. The side-by-side uses five attack texts I wrote, one of them deliberately a classic override phrase; it shows that the scanner's verdict depends on wording and the flow guard's does not. It is not a recall measurement, and I did not run it against a real agent or a real injection corpus.

## Limitations

- It needs a trusted planner that separates control (the calls) from data (the values). If the same model that read the page also writes the plan and the labels, the labels carry no information.
- It does not stop untrusted data from steering a non-sensitive argument. Text in an email body, a search query or a file path that the policy marks free is allowed and only recorded.
- Label sources must be honest. A value labeled `trusted-owner` that was in fact copied from a page is trusted.
- Labels follow only the derivation ops listed. A transformation the harness performs outside them must be labeled by the harness.
- Whole-argument granularity: a URL argument is allowed or blocked as a whole, not host by host.
- It checks a plan before it runs. It does not watch what a tool does once it runs.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py`, `python -m pytest -q` and `python mutants.py` on push and pull request.

## License

MIT, see LICENSE.
