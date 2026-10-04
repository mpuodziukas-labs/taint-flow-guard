# taint-flow-guard

A prompt-injected web page, email or file steers an agent into sending data to an attacker, and a pattern scanner misses the paraphrased or non-English wording; this guard ignores wording and blocks by where a value came from.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

## Results

| bad caught | good passed |
|---|---|
| 1/1 | 1/1 |

## Honesty Statement

Synthetic data. Not production, not client data.

## Limitations

Small synthetic corpus. Replace before drawing conclusions.
