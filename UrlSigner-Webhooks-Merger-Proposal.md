# UrlSigner + Webhooks Merger Proposal

## Summary

This document proposes a way to merge the current `GoLive.UrlSigner` library and the `GoLive.Webhooks` library into a shared HTTP-signing architecture.

The recommendation is **not** to force both libraries into one identical API or one identical wire format.

Instead, the best approach is:

- extract a **shared HTTP-signing core**
- keep a **signed URL / presigned request adapter** for query-string-based signatures
- keep a **webhook / header-signed request adapter** for POST and API-style signatures

This gives a single canonical signing engine while preserving the ergonomics and wire formats that already fit each use case.

---

## Goal

Unify two similar signing approaches:

1. **UrlSigner**
   - signs URLs
   - stores signature metadata in query string parameters like `sig` and `exp`
   - works well for GET-style links and short-lived access URLs

2. **Webhooks**
   - signs HTTP requests
   - stores signature metadata in headers like `x-api-key`, `x-api-date`, `x-api-scope`, `x-api-signed-headers`, and `Authorization`
   - works well for POST requests, webhooks, and service-to-service traffic

The desired end state is one shared signing/verification model that supports both.

---

## Current State Comparison

## UrlSigner today

Current responsibilities in `GoLive.UrlSigner`:

- HMAC signing of URLs
- verification of signed URLs
- timed signing via `exp`
- query-string signature transport via `sig`
- ASP.NET Core authentication support through `SignedUrlHandler`

### Main traits

- signs path + query
- excludes fragment from the signature
- currently supports query canonicalization so query order no longer matters
- optionally uses `token` in the query for authenticated access flows

### Strengths

- simple public API
- easy to use for presigned links
- good fit for download links and temporary access URLs
- now has decent canonical query handling and test coverage

### Limits

- body is not part of the signature
- signed headers are not part of the model
- HTTP method is not currently part of the signature model
- key lookup / key id is not part of the public contract

---

## Webhooks today

Current responsibilities in `GoLive.Webhooks`:

- signs outgoing `HttpRequestMessage`
- verifies incoming `HttpRequest`
- canonicalizes:
  - method
  - path
  - query
  - selected headers
  - payload hash
- derives a request signature from a secret key, service scope, and request timestamp

### Current wire format

Headers include:

- `x-api-key`
- `x-api-date`
- `x-api-scope`
- `x-api-algorithm`
- `x-api-signed-headers`
- `Authorization`

### Strengths

- much closer to a general HTTP request-signing model
- supports body hashing
- supports signed headers
- already has a canonical request + string-to-sign concept
- supports secret-key resolution using key id and scope

### Weaknesses to fix during merge

- plain `==` signature comparison should become constant-time
- timestamp freshness window is not clearly enforced
- query canonicalization is weaker than the newer `UrlSigner` implementation
- sync-over-async exists in `HttpRequestMessage` content reads
- duplicated canonicalization logic exists between `HttpRequestMessage` and `HttpRequest`
- old framework/package choices should be modernized

---

## Core Observation

Both libraries are doing the same underlying job:

> Build a canonical representation of an HTTP request, sign it with a keyed MAC, and validate it later.

The main difference is **transport**:

- `UrlSigner` stores metadata in the **query string**
- `Webhooks` stores metadata in **headers**

That means the merge should happen at the **canonical request + signature engine** level, not at the current top-level library shapes.

---

## Recommended Architecture

## 1. Shared HTTP-signing core

Create a shared core package, conceptually something like:

- `GoLive.HttpSignatures`
- or `GoLive.Signing.Core`

This core should own:

- canonical request construction
- canonical query logic
- canonical header logic
- payload hashing
- signature generation
- signature verification
- time metadata / expiration handling
- key resolution abstractions
- verification result types

This is the reusable engine both current libraries would sit on top of.

---

## 2. Query transport adapter

Build a query-string transport adapter for presigned URLs.

This preserves the existing `UrlSigner` style:

- `sig`
- `exp`
- optional `token`
- possible future `kid` or `scope`

This adapter would be used by:

- `HmacUrlSigner<TAlg>`
- `TimedUrlSigner`
- `SignedUrlHandler`

This is effectively the evolution of the current `UrlSigner` package.

---

## 3. Header transport adapter

Build a header-based transport adapter for webhook/API request signing.

This preserves the current webhook style:

- `x-api-key`
- `x-api-date`
- `x-api-scope`
- `x-api-algorithm`
- `x-api-signed-headers`
- `Authorization`

This adapter would be used by:

- outgoing `HttpRequestMessage` signing
- incoming `HttpRequest` verification
- future webhook middleware, filters, or endpoint helpers

This is effectively the evolution of the current `Webhooks` package.

---

## Shared Core Model

## Canonical request

A transport-agnostic request model should represent:

- HTTP method
- path
- query parameters
- selected headers
- payload hash

Conceptually:

```csharp
CanonicalHttpRequest
{
    string Method
    string Path
    IReadOnlyList<QueryPair> Query
    IReadOnlyDictionary<string, string[]> Headers
    string PayloadHash
}
```

## Signature metadata

Keep transport metadata separate from the request itself:

```csharp
SignatureMetadata
{
    string Algorithm
    string? KeyId
    string? Scope
    DateTimeOffset Timestamp
    TimeSpan? MaxAge
    DateTimeOffset? ExpiresAt
    IReadOnlyList<string> SignedHeaders
}
```

This separation avoids conflating:

- app/auth payload like `token`
- key lookup metadata like `x-api-key`
- general signing metadata like timestamp and algorithm

---

## What should be shared

## 1. Canonical query logic

Use the newer `UrlSigner` query canonicalization as the shared baseline.

That means:

- deterministic sorting
- stable ordering
- raw encoded key/value comparisons
- explicit duplicate handling
- consistent separator normalization

This should replace the weaker query normalization currently in `Webhooks`.

## 2. Canonical header logic

Reuse the webhook approach conceptually:

- lowercase header names
- trimmed values
- sorted header names
- include only signed headers

This should be one shared implementation instead of separate request/request-message versions.

## 3. Payload hashing

Use a single payload hashing abstraction for:

- empty payloads
- request bodies
- buffered request reads
- `HttpRequestMessage` content

## 4. MAC algorithm handling

Both libraries should share:

- HMAC implementation plumbing
- algorithm ids
- constant-time verification
- algorithm configuration/selection

## 5. Time validation

Unify the temporal concepts:

- URL expiration via `exp`
- webhook timestamp freshness via `x-api-date`

These are both request validity controls and should come from the same core concepts.

---

## What should stay transport-specific

## Query-signed requests

Good for:

- download links
- temporary access URLs
- GET-style callbacks
- presigned links

Characteristics:

- metadata lives in query string
- compact wire format
- body usually ignored
- token/auth payload may also be in query string

## Header-signed requests

Good for:

- webhooks
- POST callbacks
- service-to-service APIs
- body-protected requests

Characteristics:

- metadata lives in headers
- request body hash matters
- specific headers are explicitly signed
- key id and scope are naturally header-based

These are two different transports over the same signing core.

---

## Important Design Recommendation

## Do not force `token` and `x-api-key` into one concept

These represent different responsibilities.

- `token` in `UrlSigner` is application/auth payload
- `x-api-key` in `Webhooks` is key lookup metadata

The core should not try to collapse them into one shared field.

Instead:

- the core signs request components and signature metadata
- the adapters decide what fields are used for auth payload vs key lookup

---

## Proposed Abstraction Layers

## Canonicalization layer

Responsible for canonical text generation only.

Examples:

- `IHttpRequestCanonicalizer`
- `IQueryCanonicalizer`
- `IHeaderCanonicalizer`
- `IPayloadHasher`

## Signature algorithm layer

Responsible for signing/verification details.

Example:

- `ISignatureAlgorithm`

Responsibilities:

- algorithm id
- keyed hash generation
- constant-time comparison

## Key resolution layer

Responsible for providing the right signing key.

Example:

- `ISigningKeyResolver`

Possible strategies:

- fixed key
- resolve by key id
- resolve by scope
- resolve by tenant
- resolve by app-specific metadata

## Transport binding layer

Responsible for how metadata is carried.

Example:

- `ISignatureTransport`

Implementations:

- query transport
- header transport

---

## Suggested Package Layout

## Shared core

- `GoLive.HttpSignatures`

Contains:

- canonical request builder
- query/header/body canonicalization
- algorithms
- metadata
- verification results
- key resolution abstractions

## Signed URL facade

- `GoLive.UrlSigner`

Contains:

- `HmacUrlSigner<TAlg>`
- `TimedUrlSigner`
- query transport-specific helpers

## Signed URL ASP.NET integration

- `GoLive.UrlSigner.Authentication`

Contains:

- `SignedUrlHandler`
- `AddSignedUrlAuthentication(...)`

## Webhook facade

- `GoLive.Webhooks`

Contains:

- outgoing request signing helpers
- incoming request verification helpers
- future middleware/filters

This keeps one implementation core and two transport-specific products.

---

## ASP.NET Core Integration Guidance

## Signed URLs

Use an authentication handler.

That continues to make sense because signed URLs often represent user or access-link authentication and naturally produce a `ClaimsPrincipal`.

So `SignedUrlHandler` remains the right model.

## Webhooks

Do not force webhook validation into exactly the same handler model.

Webhook validation is usually a request authenticity concern rather than user authentication.

Better integration points for webhook validation are likely:

- middleware
- endpoint filters
- authorization requirements
- explicit verifier services

It is still fine to create a principal in webhook scenarios if needed, but it should not be the only supported integration shape.

---

## Recommended Public API Strategy

## Preserve the current facades

Keep current entry points working:

### UrlSigner side

- `TimedUrlSigner.Sign(...)`
- `TimedUrlSigner.Verify(...)`
- `HmacUrlSigner<TAlg>`
- `AddSignedUrlAuthentication(...)`

### Webhooks side

- `Webhooks.SignRequest(...)`
- `Webhooks.VerifyRequest(...)`

Under the hood, migrate them to the shared signing engine.

This avoids breaking existing consumers while allowing the internals to converge.

---

## Migration Strategy

## Phase 1: extract shared primitives

Introduce the shared core for:

- canonical request building
- query canonicalization
- header canonicalization
- payload hashing
- MAC signing/verification
- metadata models

Keep all current public APIs unchanged.

## Phase 2: move UrlSigner to the core

Refactor `GoLive.UrlSigner` so `UrlSigner`, `TimedUrlSigner`, and `SignedUrlHandler` rely on the new core.

## Phase 3: move Webhooks to the core

Refactor `GoLive.Webhooks` to use the same core.

Fix known issues during this phase:

- constant-time signature verification
- timestamp freshness enforcement
- async payload handling
- framework modernization

## Phase 4: add optional shared advanced APIs

Once stable, expose newer abstractions if desired, such as:

- generic HTTP request signer/verifier
- shared verification result types
- transport-specific options objects

## Phase 5: optional cleanup/deprecation

After adoption, obsolete duplicate or thin wrapper APIs only if there is clear value.

---

## Immediate Improvements Recommended for Webhooks During the Merge

1. Replace plain signature comparison with constant-time verification
2. Enforce timestamp freshness / max skew
3. Remove sync-over-async body reads
4. Reuse the stronger query canonicalization already present in `UrlSigner`
5. Deduplicate canonicalization logic for `HttpRequestMessage` and `HttpRequest`
6. Enforce algorithm selection via typed configuration instead of a loosely trusted header
7. Modernize package/runtime choices

---

## Recommended First Implementation Slice

The best first milestone is:

1. extract shared canonical query logic
2. extract shared canonical request builder
3. extract shared HMAC algorithm/verifier support
4. refactor `UrlSigner` to use the shared engine
5. refactor `Webhooks` to use the shared engine
6. keep the existing public APIs intact

This provides most of the long-term value without forcing a large breaking redesign up front.

---

## Final Recommendation

Merge the two libraries around a **shared canonical HTTP request signing engine**.

Do **not** merge by stretching the current `TimedUrlSigner` API to cover webhooks directly.

Instead:

- keep `UrlSigner` as the **presigned URL / query transport** adapter
- keep `Webhooks` as the **header-signed request / webhook transport** adapter
- unify the internals into one shared request-signing core

That produces:

- one signing model
- one verification model
- one canonicalization implementation
- one crypto implementation
- preserved ergonomics for both use cases
- lower migration risk for existing consumers

