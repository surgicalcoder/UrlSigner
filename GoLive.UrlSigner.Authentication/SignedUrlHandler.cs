using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GoLive.UrlSigner.Authentication;

public class SignedUrlHandler : AuthenticationHandler<SignedUrlAuthenticationSchemeOptions>
{
    public const string SchemeName = "SignedUrl";
    private TimedUrlSigner urlSigner;
    private TokenValidationParameters jwtTokenValidationParameters;
    
    public SignedUrlHandler(IOptionsMonitor<SignedUrlAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, 
        ISystemClock clock, TimedUrlSigner urlSigner, TokenValidationParameters jwtTokenValidationParameters) : base(options, logger, encoder, clock)
    {
        this.urlSigner = urlSigner;
        this.jwtTokenValidationParameters = jwtTokenValidationParameters;
    }
    
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Query.ContainsKey("sig"))
        {
            return AuthenticateResult.Fail("Sig missing");
        }

        if (!Request.Query.ContainsKey("exp"))
        {
            return AuthenticateResult.Fail("Exp missing");
        }

        if (!Request.Query.ContainsKey("token"))
        {
            return AuthenticateResult.Fail("Token missing");
        }

        var valid = urlSigner.Verify($"{WebUtility.UrlDecode(Request.Path)}{Request.QueryString}");

        if (!valid)
        {
            return AuthenticateResult.Fail("Invalid signature");
        }

        var token = WebEncoders.Base64UrlDecode(Request.Query["token"]).AsMemory();

        try
        {
            ClaimsPrincipal principal;

            if (Options.GetPrinciple != null)
            {
                principal = await Options.GetPrinciple.Invoke(token);
            }
            else
            {
                var decoded = Encoding.UTF8.GetString(token.ToArray());
                var tokenHandler = new JwtSecurityTokenHandler();
                principal = tokenHandler.ValidateToken(decoded, jwtTokenValidationParameters, out _);
            }

            if (principal == null)
            {
                return AuthenticateResult.Fail("Method returned null");
            }
            
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (Exception e)
        {
            return AuthenticateResult.Fail(e);
        }
        
    }
}