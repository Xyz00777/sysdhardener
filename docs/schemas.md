# Input and Output Schemas

This document is Markdown prose, not a machine-readable JSON Schema file. The authoritative definitions are the Rust wire structs, and integration tests compare the field and tag tables below against them.

## Fixture envelope v1

`analyze-fixture` accepts only `schema_version: 1`. Invalid JSON, unknown versions or tags, missing fields, reversed timestamps, duplicate event IDs, invalid source IDs, and inconsistent event counts are rejected at the input boundary and map to exit code 3.

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Must be `1`. |
| `fixture_id` | string | yes | Opaque fixture identifier. |
| `first_timestamp_unix_ms` | integer | yes | Start of the declared window. |
| `last_timestamp_unix_ms` | integer | yes | End of the declared window. |
| `coverage` | enum string | yes | `complete`, `degraded`, or `unknown`. |
| `seen_events` | integer | yes | Must equal `events.length`. |
| `dropped_events` | integer | yes | Must not exceed `seen_events`. |
| `events` | array | yes | Events in wire order. |

### Fixture event

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `source_id` | string | yes | Stable `SRC-NN` identifier. |
| `event_id` | string | yes | Non-empty and unique within the fixture. |
| `timestamp_unix_ms` | integer | yes | Event timestamp. |
| `address_family` | enum string | yes | `unix`, `inet`, `inet6`, `netlink`, or `packet`. |
| `outcome` | enum string | yes | `success`, `error`, `interrupted`, or `unknown`. |
| `args` | string | yes | Opaque event arguments. |

| Field | Wire tags (JSON string) |
| --- | --- |
| `coverage` | `complete`, `degraded`, `unknown` |
| `address_family` | `unix`, `inet`, `inet6`, `netlink`, `packet` |
| `outcome` | `success`, `error`, `interrupted`, `unknown` |

A schema-valid fixture can still fail during projection with exit code 4 when its successful family set cannot be rendered by the closed concise mapping. This is intentionally a processing failure, not an input-schema failure.

## Report envelope v1

The JSON report is output-only and is written with `--json`. It always carries
`schema_version: 1`; consumers must reject versions they do not recognize.

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Always `1`. |
| `findings` | array | yes | Provisional findings. |
| `host_systemd_version` | integer or null | no | Detected host major version, if available. |
| `known_gaps` | array of strings | yes | Undelivered or otherwise known observation gaps. |
| `observed_cgroups` | array of strings | yes | Sorted, deduplicated observed cgroups. |

### Finding

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `directive` | string | yes | Canonical systemd directive name. |
| `basis` | tagged object | yes | `absence` or `observation`. |
| `observed_families` | array | yes | Families observed. |
| `recommended_families` | array | yes | Families retained by the candidate. |
| `not_observed_families` | array | yes | Known families not observed. |
| `recommended_capabilities` | array | yes | Capability drop/grant candidate values. |
| `host_supported` | boolean | yes | Runtime compatibility result. |
| `recommended_value` | string or null | no | Explicit recommended setting value for value directives. |
| `provisional` | enum string | yes | Always `provisional`. |
| `coverage` | enum string | yes | `complete`, `degraded`, or `unknown`. |
| `event_loss` | object | yes | `seen_events` and `dropped_events`. |
| `contradiction_conditions` | array | yes | Typed contradiction conditions. |
| `compatibility_risk` | object | yes | Support, verification, and source reference. |
| `validation_procedure` | enum string | yes | `confirm_no_out_of_set_use`. |
| `source_ids` | array of strings | yes | Sorted evidence source IDs. |
| `aggregate_keys` | array of strings | yes | Evidence aggregate keys. |

### Nested report objects

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `seen_events` | integer | yes | Events captured in the observation window. |
| `dropped_events` | integer | yes | Events reported as dropped. |

| Field (wire) | Type | Required | Description |
| --- | --- | --- | --- |
| `support` | enum string | yes | `supported` or `unknown`. |
| `verification` | enum string | yes | `verified`, `unverified`, or `unknown`. |
| `source_ref` | string | yes | Registry source ID supplying compatibility evidence. |

| Field | Wire tags (JSON string) |
| --- | --- |
| `provisional` | `provisional` |
| `validation_procedure` | `confirm_no_out_of_set_use` |
| `coverage` | `complete`, `degraded`, `unknown` |
| `support` | `supported`, `unknown` |
| `verification` | `verified`, `unverified`, `unknown` |
| `basis.kind` | `absence`, `observation` |
| `contradiction_conditions[].kind` | `observed_without_successful_use`, `absent_family_used_later` |
| `observed_families` / `recommended_families` / `not_observed_families` elements | `unix`, `inet`, `inet6`, `netlink`, `packet` |

## Concise projection

The first line is exactly:

```text
# WARNING: settings below are provisional and unverified; validate before use.
```

Each later line is one `RestrictAddressFamilies=` setting. There are no per-setting comments, trace IDs, or companion warning files. Unsupported family combinations fail loudly instead of being silently rewritten.
