# UrlSigner

Small .NET 10 helpers for signing URLs with HMAC, verifying signed URLs, adding expirations, and optionally authenticating ASP.NET Core requests from signed URL tokens.

## Packages

- `GoLive.UrlSigner`
- `GoLive.UrlSigner.Authentication`

## Target framework

This solution currently targets `net10.0`.

## Install

```powershell
dotnet add package GoLive.UrlSigner
dotnet add package GoLive.UrlSigner.Authentication
```

## What the library does

The core package provides:

- HMAC URL signing
- URL signature verification
- timed/expiring signed URLs
- simple factory/static helpers so you can sign or verify directly from a key

The authentication package adds:

- an ASP.NET Core authentication handler for signed URLs
- direct key-based registration, so you do **not** need to register a singleton `TimedUrlSigner`

---

## Basic URL signing

### Create a signer instance

```csharp
using System.Security.Cryptography;
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
var signer = HmacUrlSigner<HMACSHA512>.Create(key);

var signedUrl = signer.Sign("https://example.com/files/report.pdf");
var valid = signer.Verify(signedUrl);
```

### Signatures are added as `sig`

Example output shape:

```text
https://example.com/files/report.pdf?sig=...
```

If the input URL contains a fragment, the fragment is preserved in the final URL but excluded from the signature calculation.

Example:

```text
https://example.com/files/report.pdf?sig=...#download
```

---

## Timed / expiring URLs

### Create a timed signer from a key

```csharp
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
var signer = TimedUrlSigner.Create(key);

var signedUrl = signer.Sign(
	"https://example.com/files/report.pdf?token=abc123",
	TimeSpan.FromMinutes(15));

var valid = signer.Verify(signedUrl);
```

### Direct static helpers

If you do not want to create/register a signer instance first:

```csharp
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

var signedUrl = TimedUrlSigner.Sign(
	"https://example.com/files/report.pdf?token=abc123",
	TimeSpan.FromMinutes(15),
	key);

var valid = TimedUrlSigner.Verify(signedUrl, key);
```

### Choose a different HMAC algorithm

```csharp
using System.Security.Cryptography;
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

var signedUrl = TimedUrlSigner.Sign<HMACSHA256>(
	"https://example.com/files/report.pdf?token=abc123",
	TimeSpan.FromMinutes(15),
	key);
```

### Expiration parameter

Timed URLs add an `exp` query parameter and then sign the whole URL.

`exp` is stored as Unix time seconds (UTC).

Example output shape:

```text
https://example.com/files/report.pdf?token=abc123&exp=1776515100&sig=...
```

---

## ASP.NET Core authentication

`GoLive.UrlSigner.Authentication` lets you authenticate a request from a signed URL that includes:

- `token`
- `exp`
- `sig`

### Easiest registration: pass the key directly

```csharp
using GoLive.UrlSigner.Authentication;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

builder.Services
	.AddAuthentication()
	.AddSignedUrlAuthentication(key, options =>
	{
		options.GetPrincipal = static (tokenBytes, cancellationToken) =>
		{
			var claims = new[]
			{
				new System.Security.Claims.Claim("sub", "signed-url-user")
			};

			var identity = new System.Security.Claims.ClaimsIdentity(claims, SignedUrlHandler.SchemeName);
			return ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(new(identity));
		};
	});
```

This registration path creates the `TimedUrlSigner` internally from the supplied key, so you do not need a separate singleton registration.

### JWT validation path

If you do not provide `GetPrincipal`, the handler will decode `token` as a JWT string and validate it using `TokenValidationParameters`.

You can configure those directly in the scheme options:

```csharp
using GoLive.UrlSigner.Authentication;
using Microsoft.IdentityModel.Tokens;

builder.Services
	.AddAuthentication()
	.AddSignedUrlAuthentication(key, options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = "your-issuer",
			ValidAudience = "your-audience",
			IssuerSigningKey = new SymmetricSecurityKey(key)
		};
	});
```

Or register `TokenValidationParameters` in DI and let the handler resolve it there.

### Supplying your own signer factory

If you want complete control over the signer creation:

```csharp
builder.Services
	.AddAuthentication()
	.AddSignedUrlAuthentication(options =>
	{
		options.UrlSignerFactory = services => TimedUrlSigner.Create(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"));
	});
```

---

## Reserved query parameters

The library reserves these query parameter names:

- `sig`
- `exp`
- `token` (used by the auth package)

Notes:

- signing rejects URLs that already contain `sig`
- timed signing rejects URLs that already contain `exp`
- the authentication handler expects exactly one `token`, one `exp`, and one `sig`

---

## Behavioral notes

### Fragments

Fragments (`#section`) are not part of the signature calculation.

- signing preserves them in the output URL
- verification succeeds whether the fragment is present or omitted

### Query order

Current behavior ignores the original query order.

### Parameter name comparison

Reserved parameter names are matched case-insensitively.

### Authentication request target

The auth handler verifies the request using:

- `Request.PathBase`
- `Request.Path`
- `Request.QueryString`

That means the signed URL should match the request target as the app receives it.

### Time source

`TimedUrlSigner` accepts an optional `TimeProvider`, which is useful for deterministic tests.

---

## Error / failure behavior

- invalid or malformed signatures return `false` from `Verify`
- expired timed URLs return `false`
- malformed or duplicate reserved parameters return `false` during verification
- invalid input for `Sign(...)` throws argument exceptions
- the auth handler returns authentication failure if the signature, expiration, token, or principal resolution is invalid

---

## Example: create a signed download URL

```csharp
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
var token = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
	System.Text.Encoding.UTF8.GetBytes("user-123"));

var url = $"https://example.com/downloads/file.zip?token={token}";
var signedUrl = TimedUrlSigner.Sign(url, TimeSpan.FromMinutes(5), key);
```

---

## Test status

The solution includes unit tests for:

- HMAC sign/verify round-trips
- fragment preservation
- timed signing and expiration
- direct static key-based helpers
- reserved parameter rejection
- authentication registration with direct-key configuration

Additional auth-focused integration tests are still a good idea if you want end-to-end confidence in middleware/pipeline behavior.
