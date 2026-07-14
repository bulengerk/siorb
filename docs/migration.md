# Machine migration

Migration carries logical intent, not a list of source-machine backend commands.

1. On the source host, inspect receipts and adopted state with `siorb list` and
   `siorb audit`.
2. Export portable intent: `siorb migrate export --output siorb.toml`.
3. Review packages, optional entries, scopes, versions/channels, profiles, and
   backend constraints. Remove machine-private metadata.
4. Transfer the intent and, if required, a separately verified catalog snapshot.
5. On the destination, validate and plan without mutation:

   ```console
   siorb bundle validate siorb.toml
   siorb --dry-run --explain bundle plan siorb.toml
   ```

6. Resolve differences in policy, missing native mappings, architecture, scope,
   and optional packages. Save the destination-specific lock and change report.
7. Apply only after reviewing privilege, downloads, agreements, conflicts, and
   verification. Audit/reconcile afterward.

A source lock is not directly reusable on another platform. Existing unrelated
software is observed, not automatically removed or adopted. Offline migration
also requires the destination backend's indexes/payloads or verified artifacts;
a copied Siorb catalog alone is not a payload mirror.
