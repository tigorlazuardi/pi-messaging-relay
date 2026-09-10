## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues. See `docs/src/content/docs/developer/agents/issue-tracker.md`.

Create a dedicated GitHub issue for every escalation before resolution continues. Capture its source and evidence, exact resolution scope, risk route, acceptance seam, and blockers; add the issue to supervised scope.

Each implementation ticket owns at most one testable seam. Route-only escalation with an unchanged seam returns to the same ticket after the dedicated escalation issue contains the disposition and is closed; escalation that changes or adds a seam creates a new implementation ticket instead of expanding the original.

### Domain docs

Use the single-context layout. See `docs/src/content/docs/developer/agents/domain.md`.

### Documentation

Complete each feature or fix by updating affected documentation. Organize developer documentation by domain, adding a subdomain only when needed.
