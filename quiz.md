# Quiz — AWS Secrets Manager

Five scenarios. Answers are collapsed — try them from memory first.

---

## Q1. The midnight page

It's 02:00 and the on-call engineer rotates the production RDS password
manually "just to be safe", then updates the app's environment variable and
restarts the services. Everything works. Why is the senior engineer still
unhappy in the morning?

<details>
<summary>Answer</summary>

The password now exists in at least four places that are hard to audit: the
engineer's shell history / clipboard, the deployment pipeline logs, the old
and new environment variable values, and anyone who saw the incident channel.
There is no CloudTrail record of *who read* the old password, the new one is
shared by every service (one leak = total compromise), and the next rotation
will require the same risky human coordination. The fix: put the credential in
Secrets Manager, enable automatic rotation, and let apps read it at runtime —
the password should never pass through a human at all.
</details>

## Q2. Why does the rotation Lambda need `secretsmanager:GetSecretValue`?

The rotation Lambda's job is to *write* a new password. Yet every rotation
template requests read permission on the secret too. Why?

<details>
<summary>Answer</summary>

The rotation protocol is a four-step handshake: `createSecret` generates the
new password and stores it as `AWSPENDING`, `setSecret` applies it to the
database, `testSecret` verifies the new credential actually works, and
`finishSecret` flips `AWSPENDING` to `AWSCURRENT`. The `testSecret` step must
*read back* the pending version to test it against the database — without read
permission the Lambda cannot verify the credential it just created, and the
rotation would either fail or, worse, flip an untested password into
production.
</details>

## Q3. Cross-account read — IAM policy or resource policy?

Team B runs in AWS account `2222` and needs read-only access to a database
secret owned by Team A in account `1111`. Team B's admin attaches an IAM policy
with `secretsmanager:GetSecretValue` on Team A's secret ARN to Team B's role.
It doesn't work. What are they missing?

<details>
<summary>Answer</summary>

An IAM policy in account 2222 can only grant access to resources in account
2222 — it cannot reach across the account boundary on its own. Cross-account
access to a secret requires a **resource policy on the secret itself** (in
account 1111) explicitly allowing account 2222's principal. On top of that,
Team B's role still needs `kms:Decrypt` on Team A's CMK, because the secret
blob is envelope-encrypted — reading the ciphertext without the key grant is
useless. Both grants are required: resource policy for the secret, KMS key
policy (or IAM) for the key.
</details>

## Q4. The app that caches too long

An ECS service reads the DB secret once at container startup and caches it in
memory forever. Rotation is set to every 30 days. What breaks, and what's the
standard fix?

<details>
<summary>Answer</summary>

On rotation day the database password changes, but the long-lived container
still holds the old credential — every new connection fails until the task is
restarted. Standard fixes, in order of preference: (1) use the RDS JDBC-aware
driver / Secrets Manager caching client that retries with both `AWSCURRENT`
and `AWSPENDING` during the rotation window; (2) re-read the secret
periodically (e.g. every 15 minutes) or on connection failure; (3) trigger a
rolling redeploy of the service right after rotation completes. Never cache a
rotating credential for longer than the rotation interval.
</details>

## Q5. Two keys, one secret

A security review flags this setup: the secret uses the default AWS-managed
KMS key (`aws/secretsmanager`), and the app role has `secretsmanager:*` on
`*`. The team argues "it's encrypted and it works". Give two concrete reasons
the reviewer is right.

<details>
<summary>Answer</summary>

1. **No separation of duties with the AWS-managed key.** With the default key,
   anyone who can read the secret can decrypt it — the two permissions collapse
   into one. A customer-managed CMK lets you require a *separate*
   `kms:Decrypt` grant, so "can list secrets" and "can decrypt this secret"
   stay distinct, and key usage is auditable per key.
2. **`secretsmanager:*` on `*` is a lateral-movement gift.** It allows reading
   *every* secret in the account (prod DBs, API keys, OAuth tokens), plus
   deleting them or disabling rotation. Least privilege means one IAM statement
   per secret: `GetSecretValue` + `DescribeSecret` scoped to that secret's ARN,
   nothing more.
</details>

---

*Score yourself: 5/5 — you can run secrets for a team. 3–4 — solid, re-read the
rotation handshake. Below 3 — start from the README's TL;DR and try again.*
