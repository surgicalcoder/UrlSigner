# UrlSigner

Small .NET 10 helpers for signing URLs with HMAC, verifying signed URLs, adding expirations, and optionally authenticating ASP.NET Core requests from signed URL tokens.

## Packages

- `GoLive.UrlSigner`
- `GoLive.UrlSigner.Authentication`
- `GoLive.UrlSigner.MinimalApis`

## Target framework

This solution currently targets `net10.0`.

## Install

```powershell
dotnet add package GoLive.UrlSigner
dotnet add package GoLive.UrlSigner.Authentication
dotnet add package GoLive.UrlSigner.MinimalApis
```

## What the library does

The core package provides:

- HMAC URL signing
- URL signature verification
- timed/expiring signed URLs
- simple factory/static helpers so you can sign or verify directly from a key

The authentication package adds:

- an ASP.NET Core authentication handler for signed URLs
- an MVC/controller attribute for plain signed URL validation
- direct key-based registration, so you do **not** need to register a singleton `TimedUrlSigner`

The Minimal API package adds:

- endpoint filters for routes that only need signed URL validation
- endpoint filters for routes that need signed URL validation **and** `token` principal resolution

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
	"https://example.com/files/report.pdf",
	TimeSpan.FromMinutes(15));

var valid = signer.Verify(signedUrl);
```

### Direct static helpers

If you do not want to create/register a signer instance first:

```csharp
using GoLive.UrlSigner;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

var signedUrl = TimedUrlSigner.Sign(
	"https://example.com/files/report.pdf",
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
	"https://example.com/files/report.pdf",
	TimeSpan.FromMinutes(15),
	key);
```

### Expiration parameter

Timed URLs add an `exp` query parameter and then sign the whole URL.

`exp` is stored as Unix time seconds (UTC).

Example output shape:

```text
https://example.com/files/report.pdf?exp=1776515100&sig=...
```

---

## Plain signed URLs vs full token support

This is the most important distinction in the library:

## Plain signed URL validation

Use this when you only want to know:

- was the URL signed correctly?
- is it still within its expiration window?

In this mode, the URL contains:

- `exp`
- `sig`

No `token` is required.

## Full token support

Use this when you want the signed URL to also carry an identity/auth payload that becomes a `ClaimsPrincipal`.

In this mode, the URL contains:

- `token`
- `exp`
- `sig`

Important:

- the core `GoLive.UrlSigner` package does **not** add `token` automatically
- **you** add `token` to the URL before signing it
- the auth/minimal-token integrations decode and validate that `token` after the URL signature passes

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

### MVC / controller examples

#### Controller route that only checks URL signing

This route validates `exp` + `sig` only. It does **not** require `token` and does **not** create a principal.

First register MVC signed URL validation:

```csharp
using GoLive.UrlSigner.Authentication;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

builder.Services.AddControllers();
builder.Services.AddSignedUrlValidation(key);
```

Then decorate the controller or action with `[RequireSignedUrl]`:

```csharp
using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("downloads")]
public class DownloadsController : ControllerBase
{
	[RequireSignedUrl]
	[HttpGet("plain")]
	public IActionResult Plain()
	{
		return Ok("Signed URL is valid.");
	}
}
```

You can also put `[RequireSignedUrl]` on the controller class if every action in that controller should require a valid signed URL.

#### Controller route with full token support

This route requires `token` + `exp` + `sig` and produces `HttpContext.User` / `User`.

```csharp
using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("downloads")]
public class DownloadsController : ControllerBase
{
	[Authorize(AuthenticationSchemes = SignedUrlHandler.SchemeName)]
	[HttpGet("secure")]
	public IActionResult Secure()
	{
		var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
		return Ok($"Signed URL authenticated for {userId}.");
	}
}
```

So in MVC terms:

- **plain route** = `AddSignedUrlValidation(...)` + `[RequireSignedUrl]`
- **full token route** = `AddSignedUrlAuthentication(...)` + `[Authorize(AuthenticationSchemes = SignedUrlHandler.SchemeName)]`

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

## Minimal API support

`GoLive.UrlSigner.MinimalApis` adds endpoint filters for the same two lanes:

- plain signed URL validation
- full token support

### Minimal API route that only checks URL signing

This route validates `exp` + `sig` only.

```csharp
using GoLive.UrlSigner.MinimalApis;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

app.MapGet("/downloads/plain", () => Results.Ok("Signed URL is valid."))
	.RequireSignedUrl(key);
```

### Minimal API route with full token support

This route validates `token` + `exp` + `sig` and sets `HttpContext.User`.

```csharp
using GoLive.UrlSigner.MinimalApis;
using System.Security.Claims;
using System.Text;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

app.MapGet("/downloads/secure", (HttpContext context) =>
{
	var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
	return Results.Ok($"Signed URL authenticated for {userId}.");
})
	.RequireSignedUrlToken(key, options =>
	{
		options.GetPrincipal = static (tokenBytes, cancellationToken) =>
		{
			var userId = Encoding.UTF8.GetString(tokenBytes.Span);
			var identity = new ClaimsIdentity(
				new[] { new Claim(ClaimTypes.NameIdentifier, userId) },
				"SignedUrlMinimalApi");

			return ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(identity));
		};
	});
```

### Minimal API route with JWT validation

If you do not supply `GetPrincipal`, the Minimal API token filter can also validate `token` as a JWT string.

```csharp
using GoLive.UrlSigner.MinimalApis;
using Microsoft.IdentityModel.Tokens;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

app.MapGet("/downloads/jwt", (HttpContext context) =>
{
	return Results.Ok(context.User.Identity?.Name ?? "authenticated");
})
	.RequireSignedUrlToken(key, options =>
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

So in Minimal API terms:

- **plain route** = `.RequireSignedUrl(...)`
- **full token route** = `.RequireSignedUrlToken(...)`

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
- the Minimal API token filter also expects exactly one `token`, one `exp`, and one `sig`

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
- the Minimal API filters return `401 Unauthorized` when the signature, expiration, token, or principal resolution is invalid

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
- Signed URL authentication handler behavior
- MVC/auth-style ASP.NET Core integration behavior
- Minimal API plain signed URL filters
- Minimal API full token-support filters

The solution now includes end-to-end integration coverage for the authentication and Minimal API support packages.
