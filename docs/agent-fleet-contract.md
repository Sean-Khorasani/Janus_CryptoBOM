# Agent Fleet And Scan History Contract

This contract defines the identities and state used by the fleet, scan-history,
report, and contextual exposure views.

## Canonical Records

- **Agent**: stable endpoint identity keyed by `host_uuid`. Mutable fields
  describe its latest registration and heartbeat.
- **Connection session**: starts on registration/re-registration and records
  controller-observed IP, agent version, last heartbeat, and disconnection.
- **Scan run/report**: immutable telemetry receipt keyed by `scan_id`
  (`telemetry_id`). It retains agent/OS/network identity at scan time.
- **Finding occurrence**: immutable evidence that a finding appeared in one
  scan. It is separate from the mutable current-finding lifecycle status.
- **Progress event**: durable heartbeat snapshot containing phase/status,
  current path, percentage, processed files, CPU, and memory.

## State Rules

- An agent is `offline` when its last heartbeat is older than the configured
  stall threshold. Other states come from the latest heartbeat.
- A scan is `completed` only after its telemetry payload is durably stored.
- Repeated findings create new occurrences while updating the current open
  finding record. Historical occurrences are never overwritten.
- Controller-observed source IP is authoritative. DNS and endpoint-reported
  addresses are descriptive and must not be used for authorization.
- Fleet lists, histories, findings, and components are server-paginated and
  deterministically sorted with a stable identity tie-breaker.

## Contextual Findings Rules

- No graph selection: show highest-priority current findings.
- Agent node: show findings from that agent's latest completed scan.
- Component/file node: show findings for that exact component/file.
- Algorithm node: show findings for that algorithm in the active scope.
- The exposure graph is bounded and never represents the complete fleet.
