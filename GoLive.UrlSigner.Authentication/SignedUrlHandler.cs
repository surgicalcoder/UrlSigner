using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GoLive.UrlSigner.Authentication;

public class SignedUrlHandler : AuthenticationHandler<SignedUrlAuthenticationSchemeOptions>
{
    public const string SchemeName = "SignedUrl";

    public SignedUrlHandler(IOptionsMonitor<SignedUrlAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }
    
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!TryGetSingleQueryValue("sig", out _, out var sigFailure))
        {
            return sigFailure;
        }

        if (!TryGetSingleQueryValue("exp", out _, out var expFailure))
        {
            return expFailure;
        }

        if (!TryGetSingleQueryValue("token", out var encodedToken, out var tokenFailure))
        {
            return tokenFailure;
        }

        var urlSigner = ResolveUrlSigner();

        if (urlSigner is null)
        {
            return AuthenticateResult.Fail("Signed URL authentication is not configured with a TimedUrlSigner or UrlSignerFactory.");
        }

        var requestTarget = string.Concat(Request.PathBase.ToUriComponent(), Request.Path.ToUriComponent(), Request.QueryString.ToUriComponent());
        var valid = urlSigner.Verify(requestTarget);

        if (!valid)
        {
            return AuthenticateResult.Fail("Invalid signature");
        }

        try
        {
            var token = WebEncoders.Base64UrlDecode(encodedToken).AsMemory();
            ClaimsPrincipal? principal;

            if (Options.GetPrincipal != null)
            {
                principal = await Options.GetPrincipal(token, Context.RequestAborted).ConfigureAwait(false);
            }
            else
            {
                principal = ValidateJwtToken(token.Span);
            }

            if (principal is null)
            {
                return AuthenticateResult.Fail("Principal resolver returned null.");
            }
            
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (Exception e)
        {
            return AuthenticateResult.Fail(e);
        }
        
    }

    private TimedUrlSigner? ResolveUrlSigner()
    {
        if (Options.UrlSignerFactory is not null)
        {
            return Options.UrlSignerFactory(Context.RequestServices);
        }

        return Context.RequestServices.GetService<TimedUrlSigner>();
    }

    private ClaimsPrincipal ValidateJwtToken(ReadOnlySpan<byte> token)
    {
        var validationParameters = Options.TokenValidationParameters ?? Context.RequestServices.GetService<TokenValidationParameters>();

        if (validationParameters is null)
        {
            throw new InvalidOperationException("TokenValidationParameters must be configured when GetPrincipal is not supplied.");
        }

        var decoded = Encoding.UTF8.GetString(token);
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.ValidateToken(decoded, validationParameters, out _);
    }

    private bool TryGetSingleQueryValue(string key, out string value, out AuthenticateResult failureResult)
    {
        if (!Request.Query.TryGetValue(key, out var values) || values.Count == 0)
        {
            value = string.Empty;
            failureResult = AuthenticateResult.Fail($"{key} missing");
            return false;
        }

        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            value = string.Empty;
            failureResult = AuthenticateResult.Fail($"{key} must be supplied exactly once");
            return false;
        }

        value = values[0]!;
        failureResult = AuthenticateResult.NoResult();
        return true;
    }
}