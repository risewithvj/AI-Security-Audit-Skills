## What & why

<!-- One or two lines: what this changes and the problem it solves. Link issues: Closes #123 -->

## Type

- [ ] Bug fix
- [ ] New check / rule / stack
- [ ] Report or prompt improvement
- [ ] Docs / landing page
- [ ] Engine / CI

## Checklist

- [ ] No change to the **evidence bar** — findings still need file + line + proof.
- [ ] Read-only preserved — nothing modifies, runs or contacts a target.
- [ ] Ran `python -m unittest discover -s tests` locally (if engine touched).
- [ ] No secrets, private source, or AI-attribution lines in the diff.
- [ ] Docs / CHANGELOG updated if behaviour changed.

## Notes for the reviewer

<!-- Anything tricky, trade-offs, or follow-ups. -->
