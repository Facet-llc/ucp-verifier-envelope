# Governance

This org owns one thing: the neutral **verifier-attestation envelope** and its
conformance requirements. It owns nothing about what any individual claim means.

## What the org governs

- The envelope: the Signals entry shape, the trust model, the verifier and
  consumer responsibilities, and the conformance bar a profile must clear to be
  listed in the registry.
- The registry itself: which signals are listed, and the entry evidence each
  one shipped (a runnable verifier over committed vectors, per section 8 of the
  envelope spec).

Changes to the envelope or the conformance bar are decided by the maintainers
together. No single maintainer, and no single maintainer's company, decides them
alone.

## What the org does NOT govern

- **The meaning of a claim type stays with the issuer who owns its profile.**
  What `risk` asserts, what `identity` asserts, what a `decision-provenance`
  receipt binds to and for how long: that is defined in the issuer's own,
  externally versioned profile, and only that issuer changes it. The registry
  references a profile that meets the bar; it does not take ownership of the
  profile's semantics, and it cannot redefine a claim by committee.
- **An issuer's keys, verifier, and production service.** Those live with the
  issuer and never transfer here.

## Why this split

The whole proposal rests on the envelope being neutral of every party while each
verdict stays the responsibility of the party that signs it. If the org could
redefine what a claim means, it would become a party to the claim, which is
exactly the position an external verifier must never hold. Keeping envelope
governance here and claim semantics with each issuer is what lets "neutral" be
true rather than asserted.

## Maintainers

The org is co-maintained by the independent issuers who have shipped a
conformant profile. Being a maintainer of the envelope carries no weight over
another issuer's profile. Adding or removing a maintainer is a decision of the
current maintainers together.
