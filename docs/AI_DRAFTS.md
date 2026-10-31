# Config drafting: current behavior

For the latest local generation/repair and SIEM workflow evidence, see
[AI_LOCAL_TESTS.md](AI_LOCAL_TESTS.md). Live model quality is a separate check.

AI writes a **proposal**. Go validates it; the engine collects and maps data.
The engine works without an LLM when supplied with a correct manual config.

## New vendor

1. Choose the product and supported data class.
2. State the exact dataset and scope (public, repository, organization, account
   or enterprise). Supply up to three trusted public API-reference URLs.
3. The backend fetches public HTTPS text without credentials or redirects. It
   rejects internal destinations and bounds document size, time and concurrency.
4. The hosted model sees public reference excerpts and the requested dataset.
   Customer notes, existing secret names, credential values and collected records
   are excluded. Fill customer-specific inputs locally after drafting.
5. Go checks both the config schema and citations for the actual execution
   settings. It rejects invented paths, fields, wrong scope and unsupported
   settings. Repairs are bounded; failing proposals are not executable results.
6. Review the cited documents, fill local inputs, test the connection, then
   activate. The UI performs validation and preview before activation. The API
   does not enforce a separate two-person approval process.

The mechanism is vendor-neutral, but it does not support every API. It currently
targets HTTPS GET/JSON, the engine's documented authentication/pagination methods
and five OCSF classes. JavaScript-only, private, oversized or insufficient docs
may require a more focused public reference or a manually reviewed config.
Literal evidence does not automatically establish trust, eligibility or semantic
correctness. For example, a repository object is not a user record.

Example request body for `POST /ai/draft`:

```json
{
  "product": "GitHub",
  "data": "user_inventory",
  "dataset": "repository contributors",
  "scope": "repository",
  "documentation_urls": [
    "https://docs.github.com/en/rest/repos/repos#list-repository-contributors"
  ]
}
```

Do not put secrets or private company information in product, dataset, scope or
public URLs. They are transmitted to the selected hosted provider.

## Reviewed examples

The UI also offers GitHub public users, repository contributors and public
organization members; NVD's KEV CVE subset; and CISA's official KEV mirror.
These return a reviewed contract with official documentation and explicit local
inputs. They are examples, not the only vendors the generic flow can support.

`reviewed_profile_fallback` means the model proposed something different and the
server retained its reviewed config. `documented_candidate` means the generic
draft passed literal evidence checks. Neither status means the customer's key,
subscription or selected resource has already been tested.

Choose either a reviewed profile or an explicit dataset/scope with public docs;
mixing the two is rejected. No Enterprise endpoint is silently substituted for a
public repository request. Missing email/status/login facts remain absent.

## Provider and failure behavior

Groq and Gemini use API keys from private environment settings. Bedrock's adapter
exists but has not been tested with a live account here. Do not claim live AWS
authorization based on application IAM tests.

The config drafter sends no vendor credentials to the LLM. The Go engine later
loads a local secret by name, checks its tenant/host binding and sends it only to
the permitted destination. AI-provider keys stay in request headers and do not
follow redirects.

Network outages, provider overload and invalid model answers can still prevent
draft generation. They must leave no saved config and no collection job. Manual
configs keep working. Known token usage is recorded; missing provider usage is
unknown, not zero-cost, and the conservative reservation is retained.

See [VERIFICATION.md](VERIFICATION.md) for exact test results and remaining gaps.
