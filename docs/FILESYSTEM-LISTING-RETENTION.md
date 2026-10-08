# Filesystem listing retention

The desktop workspace retains at most two decoded filesystem listings with an
aggregate budget of 64 MiB of logical UTF-8 String payload. Selecting or inserting
a listing moves its evidence UUID to the most recently used end. Insertion evicts
older listings until both limits hold. A replacement removes its old generation
before admission; if the new cost exceeds the budget, the old generation is also
removed so the workspace cannot continue showing stale results.

`FilesystemListingRetention` tracks UUIDs, precomputed costs and LRU order. The
workspace owns the actual `[UUID: EnumerationResult]` dictionary and removes the
UUIDs returned by each insertion. This operation affects only decoded in-memory
listings. It does not delete persisted enumeration artifacts or modify evidence.

`FilesystemListingStringCost.measure` runs synchronously on a worker before a
listing is published. It validates count limits and the bounded header with the
shared engine rules, then validates each filesystem row and checks unique IDs.
The scan checks cancellation before and after header validation, within every
128 measured String fields, at every 128 file rows, and before returning. The
existing bounded header validator itself is not interruptible. The scan uses
checked integer addition, stops as soon as the String payload exceeds 64 MiB,
and never encodes or decodes the result to compute cost. Separately stored source
scope paths have their own UTF-8 bounds even when Swift considers their composed
and decomposed Unicode spellings equal.

The cost includes every stored String occurrence exactly once: engine and patch
versions; source paths and identity paths; container hash dictionary keys and
values; option image type and timezone; image type, logical hash and optional
image paths; volume IDs and filesystem names; file IDs, paths and names; optional
recovery status and warnings; each optional created, modified and accessed civil
timestamp's civil text and timezone; and result warnings. Repeated text in
different fields contributes for each field. Nil contributes zero. Enum raw
values, computed hash-scope strings, dates and numeric fields contribute zero.

This is a deterministic logical String payload budget, not an RSS ceiling or a
claim about Swift allocator overhead. UTF-8 bytes preserve Thai and combining
text correctly. A legal listing whose complete serialized JSON fits the engine's
64 MiB artifact cap also fits this String budget, because it counts stored value
strings rather than adding JSON keys, quoting, escaping or record estimates.

Synthetic tests cover independent all-field arithmetic, optional provenance,
Unicode byte boundaries, strict record validation, cancellation, checked
overflow, count and aggregate admission, selection order and rejected replacement.
