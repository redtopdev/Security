using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedTop.Security.OAuthService.Providers
{
    /// <summary>
    /// Facebook OAuth provider
    /// </summary>
    /// <seealso cref="MD.OAuthProviders.Abstract.IOauthProvider" />
    public class FacebookProvider : IOauthProvider
    {
        /// <summary>
        /// Authorizes the specified model.
        /// </summary>
        /// <param name="model">The model.</param>

        public dynamic Authorize(ProviderAndAccessToken model)
        {
            try
            {
                var fbclient = new Facebook.FacebookClient(model.Token);
                dynamic fb = fbclient.Get("/me?locale=en_US&fields=name,email");
                return new
                {
                    id = fb.id,
                    userName = fb.email != null ? fb.email : fb.name != null ? fb.name : fb.id
                };

            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
