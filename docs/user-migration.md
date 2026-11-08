# Backend-neutral user migration

Any backend can use `identityctl` directly when its exporter produces the
canonical bulk envelope. Identity does not need access to that backend's database
or understand its local schema. The source system chooses a stable `source` and
an `externalId` that uniquely identifies each local account.

Prepare two private documents with the same records:

- `customer.validate.json` uses `mode: "VALIDATE_ONLY"` and a validation-specific
  idempotency key;
- `customer.create.json` uses `mode: "CREATE_ONLY"` and a different creation key.

An idempotency key may be replayed only with the same import content. Changing
the mode or records while reusing a key is rejected as drift.

Submit validation first and retain the job ID returned by the command:

```bash
tenant_id='TENANT_UUID'

identityctl users import "$tenant_id" customer.validate.json
identityctl users imports "$tenant_id" 0
identityctl users import-results "$tenant_id" VALIDATION_JOB_ID 0
```

Wait for `SUCCEEDED`, check that `processedItems`, `succeededItems` and
`totalItems` are equal, and inspect every result page. A successful validation
does not create users and new records therefore have no final `sub` yet. Repeat
`import-results` with pages `1`, `2`, and so on until the response has
`last: true`.

Submit the creation document only after checking the validation and target
tenant:

```bash
identityctl users import "$tenant_id" customer.create.json
identityctl users imports "$tenant_id" 0
identityctl users import-results "$tenant_id" CREATE_JOB_ID 0
```

The creation job is complete only when its status is `SUCCEEDED`, all counts
match and every paginated result has `status: "SUCCEEDED"` and a non-null
`subject`. Again, increment the page until `last: true`. Each result is the
authoritative mapping:

```json
{
  "externalId": "customer-user-42",
  "email": "user@example.com",
  "subject": "opaque-identity-subject",
  "status": "SUCCEEDED"
}
```

The source backend must consume **all** result pages, verify exact coverage and
uniqueness by `externalId`, then transactionally store its local account binding
to the target `(issuer, subject)`. Email is a drift check and must never be the
binding key. Identity does not migrate product roles, permissions, memberships
or business data, and `identityctl` does not call a customer backend's binder or
cutover operation.

Identity profile exports are generic as well:

```bash
identityctl users export "$tenant_id" customer-export-20261013
identityctl users exports "$tenant_id" 0
identityctl users export-records "$tenant_id" EXPORT_JOB_ID 0
identityctl users export-download "$tenant_id" EXPORT_JOB_ID > identity-users.ndjson
```

Profile exports intentionally exclude password hashes, MFA secrets, recovery
codes and upstream credentials. They are suitable for reconciliation, not for
reconstructing an authentication migration source.
