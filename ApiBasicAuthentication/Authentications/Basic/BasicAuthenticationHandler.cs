using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace ApiBasicAuthentication.Authentications.Basic
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {

        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Key..."));
            }

            var authorizationHeader = Request.Headers["Authorization"].ToString();

            if (!authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(AuthenticateResult.Fail("Authorization header does not start with 'Basic'..."));
            }

            var authBase64Decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorizationHeader.Replace("Basic ","",StringComparison.OrdinalIgnoreCase)));
            var authSplit = authBase64Decoded.Split(new[] { ':' }, 2);

            if(authSplit.Length != 2)
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization header format..."));
            }

            var clientId     = authSplit[0];
            var clientSecret = authSplit[1];

            if (clientId != "roundthecode" || clientSecret != "roundthecode")
            {
                return Task.FromResult(AuthenticateResult.Fail("The secret is incorrect..."));
            }

            var client = new BasicAuthenticationClient
            {
                AuthenticationType = BasicAuthenticationDefault.AuthenticationScheme,
                IsAutheticated = true,
                Name = clientId
            };

            var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(client, new[] {
                new Claim(ClaimTypes.Name, clientId)
            }));
                    

        }
    }
}
