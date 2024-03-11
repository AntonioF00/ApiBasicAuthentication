using Microsoft.AspNetCore.Authorization;

namespace ApiBasicAuthentication.Authentications.Basic.Attribute
{
    public class BasicAuthorizationAttribute : AuthorizeAttribute
    {
        public BasicAuthorizationAttribute()
        {
            AuthenticationSchemes = BasicAuthenticationDefault.AuthenticationSchemes;
        }
    }
}
