# libeval

Policy evaluator library used by the ZPR visa service (`vs`) and the policy
tester (`zpt`).

Given a description of network traffic (source/destination actors and packet
details), libeval compares it against a compiled ZPR policy and returns an
allow/deny decision.


## Main Concepts

- **Policy** -- A compiled ZPL policy loaded from a binary file (Cap'n Proto
  format). Policies contain communication rules and join policies.
- **Actor** -- A network entity described by a set of key-value attributes
  (address, services, role, tags, etc.).
- **EvalContext** -- The evaluation engine. Holds a policy and exposes methods
  to evaluate packets and approve connections.
- **Join Policy** -- Rules that govern whether an actor is allowed to connect
  and which attributes/services it receives upon joining.

### Two-Stage Evaluation

Evaluation is split into two stages to support route-aware policy decisions:

**Stage 1 — `EvalContext::eval_request`** returns a `PartialEvalResult`:

| Variant | Meaning |
|---|---|
| `Deny(FinalDeny)` | Denied regardless of route; no further evaluation needed. |
| `AllowWithoutRoute(hits)` | Allowed regardless of route; no further evaluation needed. |
| `NeedsRoute(RouteResidualEvaluator)` | Route information is required to reach a final decision. |

`FinalDeny` distinguishes between a deny-policy match (`Deny(hits)`) and no
matching policy at all (`NoMatch(msg)`).

**Stage 2 — `RouteResidualEvaluator::eval_route`** (scaffold, not yet
implemented) takes the residual evaluator from stage 1 along with a `Route`
and returns a `FinalEvalResult` (`Allow`, `Deny`, or `NoMatch`).

### Supporting Types

- **`Hit`** -- A single matching policy line, carrying its index, direction
  (`Forward`/`Reverse`), an optional signal, and an optional route.
- **`VisaProps`** -- The information needed to create a visa (addresses, ports,
  protocol, constraints, communication options).
- **`EvalError`** -- Typed errors covering Cap'n Proto decoding, unsupported
  protocols, missing attributes/claims, and internal errors.


## Usage

```rust
use libeval::eval::EvalContext;
use libeval::eval_result::{FinalDeny, PartialEvalResult};
use libeval::policy::Policy;
use libeval::pio::load_policy;

// Load a compiled policy from disk.
let policy = load_policy(path, min_version)?;

// Create the evaluation context.
let ctx = EvalContext::new(Arc::new(policy));

// Stage 1: evaluate a packet against policy.
let partial = ctx.eval_request(&src_actor, &dst_actor, &packet)?;

match partial {
    PartialEvalResult::Deny(FinalDeny::Deny(hits))  => { /* deny */ }
    PartialEvalResult::Deny(FinalDeny::NoMatch(msg)) => { /* no policy */ }
    PartialEvalResult::AllowWithoutRoute(hits)       => { /* allow */ }
    PartialEvalResult::NeedsRoute(residual) => {
        // Stage 2: provide a route and get a final decision.
        let final_result = residual.eval_route(&src_actor, &dst_actor, &packet, &route)?;
    }
}
```


## Supported Protocols

- **TCP** -- Port-based matching with SYN/ACK flag awareness.
- **UDP** -- Port-based matching.
- **ICMPv6** -- Type/code matching (source port = ICMP type, dest port = ICMP
  code).


## Building

```bash
make all
```
