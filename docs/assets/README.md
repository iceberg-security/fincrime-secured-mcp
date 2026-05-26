# Demo assets

This directory holds the demo recordings linked from the top-level
`README.md` and `docs/launch-post.md`.

## Required asset

- `demo.gif` — a 60–90 second screencast of an analyst triaging one alert
  end-to-end through the plugin. Capture the audit log filling in, the
  Grafana dashboard updating, and the final draft narrative.

`demo.gif` is **not** committed to the repo as a placeholder so that the
git tree stays small; the launch checklist (US-034) is to record it from
the real M3 stack against the `mule` persona and commit it before the
public push to GitHub.

Recommended capture flow:

```bash
make compose-up
make load-fixtures
# In Cowork, run the orchestrator skill against alert-mule-001
# Record at 1280x800, export as GIF at 12 fps, target <8 MB
```

When the file lands here it will satisfy the
`README.md` demo embed and the launch post asset reference without any
markup changes.
