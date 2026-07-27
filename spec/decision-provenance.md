# Decision provenance

A signature proves a claim is authentic and unmodified. It does not, on its own,
say **what produced the claim**. For an identity attestation that gap is small:
the issuer either knows who the agent is or it does not. For a claim type that
carries a *judgement*, like risk, the gap is the whole dispute. Two verdicts can
be equally authentic, disagree, and both be correct, because they were decided
under different rules months apart.

This document specifies the two fields that close that gap, and what a consumer
can do with them. It is written from the risk profile
([`claim-types/risk.md`](claim-types/risk.md)), which implements it today, but
nothing here is risk-specific: any claim type whose payload is an opinion rather
than a fact SHOULD carry the same two fields.

## The two fields

| field | answers |
|---|---|
| `policy_version` | Which rules were in force when this was decided. |
| `model_version` | Which scoring implementation produced the accompanying score. |

Both are **inside the signed payload**. That placement is the entire point: if
either lived beside the JWS as metadata, the issuer could restate later which
policy applied, and the record would be back to depending on the issuer's word.
Signed, the pairing of verdict and rule set is fixed at decision time by someone
who cannot quietly revise it.

They are separate because they change for different reasons and on different
clocks. A policy changes when a human decides the rules should differ. A model
changes when the implementation that scores against those rules is replaced.
Collapsing them into one version string makes it impossible to tell a rule change
from a code change after the fact, which is exactly the question an audit asks.

## What a consumer may rely on

1. `decision` is the only field a consumer is required to act on.
2. `score` is advisory. It explains a decision; it does not override one. A
   consumer MUST NOT re-derive a different decision from the score alone, because
   the score's meaning is defined by the `model_version` that produced it.
3. `policy_version` and `model_version` are opaque identifiers. A consumer MUST
   NOT parse them for ordering or comparison. They are keys for lookup, not
   versions to reason about numerically.

## What the issuer owes

An issuer that publishes these fields SHOULD make them resolvable: given a
`policy_version`, a third party should be able to find out what that policy said.
An identifier nobody can look up is decoration.

The minimum is a published, dated record of policy revisions. Anything stronger is
the issuer's choice, and the envelope does not mandate a mechanism.

### How the risk profile does it

`did:web:fidacy.com` publishes an aggregate calibration record at
[`https://api.fidacy.com/v1/transparency`](https://api.fidacy.com/v1/transparency),
unauthenticated, reporting the current `model_version` and how its decisions
compare against the latest human ground-truth: accuracy, a cost-weighted error
that penalises approving what should have been denied, and whether the residual
error favours the fail-safe direction. Counts and rates only, no row, case, tenant
or personal data.

Separately, each verdict is hash-chained into a tamper-evident audit whose
checkpoints are anchored to a public blockchain, so the *ordering* of decisions is
attestable independently of the issuer as well as their content.

Neither mechanism is part of the envelope, and a conformant issuer is free to
choose another. They are named here as a worked example of what "resolvable"
means in practice, and so a reader can check whether the risk profile actually
does what this document asks of an issuer.

## Why this is not a scoring standard

Nothing here constrains how a verdict is decided, and it should not. Two issuers
with incompatible risk models can both be conformant. What is constrained is that
each verdict says, in bytes nobody can revise afterwards, which rules it was
decided under.

That is the difference between an opinion and evidence. An opinion tells you what
the issuer thinks. Evidence tells you what the issuer thought, when, and under
which rules, in a form that survives the issuer changing its mind.
