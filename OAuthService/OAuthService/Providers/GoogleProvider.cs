using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;

namespace RedTop.Security.OAuthService.Providers
{
    /// <summary>
    /// Google OAuth provider
    /// </summary>
    /// <seealso cref="MD.OAuthProviders.Abstract.IOauthProvider" />
    internal class GoogleProvider : IOauthProvider
    {
        /// <summary>
        /// Authorizes the specified model.
        /// </summary>
        /// <param name="model">The model.</param>
        public dynamic Authorize(ProviderAndAccessToken model)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    //api to get the data from google.
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                       model.Token);
                    var response = client.GetAsync("https://www.googleapis.com/oauth2/v2/userinfo?fields=email%2Cid%2Cname").Result;
                    if (response.IsSuccessStatusCode)
                    {
                        dynamic userInfo = JsonConvert.DeserializeObject(response.Content.ReadAsStringAsync().Result);
                        return new
                        {
                            id = userInfo.id,
                            userName = userInfo.email != null ? userInfo.email : userInfo.name != null ? userInfo.name : userInfo.id
                        };
                    }
                    return new
                    {
                        id = string.Empty,
                        userName = string.Empty
                    };
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}