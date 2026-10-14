# Measured install outcomes

Nine invocations: three authored archive variants × three policies. One run per cell, not an attack-rate estimate.

| Archive | Version only | Saved hash | Fresh hash |
|---|---|---|---|
| original | installed 42 | installed 42 | installed 42 |
| changed_data | installed 99 | hash mismatch; no installed files | installed 99 |
| benign_metadata | installed 42 | hash mismatch; no installed files | installed 42 |

The changed-data archive retains the same name and version. Saved hash uses the original archive digest; Fresh hash uses a newly calculated digest of the archive currently supplied. Both hash methods use the same pip verification options.

An ordinary metadata edit is also rejected by Saved hash. Matching bytes is not a test for malicious intent. Fresh hash accepting changed bytes exposes the trust-acquisition limit, not a SHA-256 failure.

No package was imported. The sink is the installed value.txt read by the trusted harness. The empty __init__.py contains no executable statements. See run.json for exact hashes, requirements, commands, normalized pip logs and target file lists.
