# Verifying this repository

Purpose: demonstrates a plan check that blocks tool calls whose tool choice or sensitive argument derives from untrusted data, whatever the wording of the injection for teams subject to model-risk, audit or change-control review.

Verify: `bash run.sh`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `mutants killed 28/28`

Scope: synthetic data, fixed seed, offline, under 60 seconds.

Limitations: Needs a trusted planner that separates control from data. Untrusted data steering a non-sensitive argument is allowed and only recorded. Label sources must be honest. Granularity is the whole argument. It checks a plan before it runs and does not watch tool behavior.

Anything else = not verified.
