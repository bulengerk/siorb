# State, receipts, and recovery

Siorb state lives in the platform-standard application data directory. System
receipts are used only for system-scope operations and receive the minimum
required privilege. Files use atomic replacement and forward-migratable versions;
the transaction journal is append-only.

A receipt records logical package ID, exact native identity/source/backend,
requested and observed version, scope/channel/architecture, catalog and policy
fingerprints, timestamp, verification result, directly owned files when known,
transaction ID, and whether state was installed, adopted, or only observed. The
normative serialized contract is `schemas/v1/receipt.schema.json`.

## Journal lifecycle

Each step records start, completion/failure, verification, and receipt commit.
On interruption, a later invocation detects the unfinished transaction. A
native backend may have changed state before returning an error; therefore Siorb
does not mark a transaction rolled back unless the backend proves it.

Use `siorb reconcile` to compare receipts and observed backend state, inspect the
resulting plan, and only then choose repair/retry. Do not delete a journal or
receipt merely to hide drift; preserve it until the actual installed identity is
known.

## Adoption and ownership

Adoption requires exact logical-to-native confirmation and writes an `adopted`
receipt. It does not claim ownership of files managed by a native backend.
Reconciliation observes unknown software but never silently removes it.

Pins and holds constrain Siorb plans. If a backend cannot enforce the same rule
natively, external backend commands may still change the package; Siorb reports
that limitation and detects drift later.

## Corruption and backup

State parsing fails closed with an actionable reason. Recovery uses the last
valid atomic backup/journal evidence and backend observation; never synthesize a
successful verification. Back up bundle intent and receipts before migration,
but remove local usernames, private source details, and tokens before sharing.
