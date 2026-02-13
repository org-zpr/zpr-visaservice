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
- **EvalDecision** -- The result of an evaluation: `Allow`, `Deny`, or
  `NoMatch`, each carrying the list of matching policy hits.
- **Join Policy** -- Rules that govern whether an actor is allowed to connect
  and which attributes/services it receives upon joining.


## Usage

```rust
use libeval::eval::EvalContext;
use libeval::policy::Policy;
use libeval::pio::load_policy;

// Load a compiled policy from disk.
let policy = load_policy(path, min_version)?;

// Create the evaluation context.
let ctx = EvalContext::new(Arc::new(policy));

// Evaluate a packet.
let decision = ctx.eval_request(&src_actor, &dst_actor, &packet)?;
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
