namespace RedTop.Security.OAuthService.Providers
{
    /// <summary>
    /// OAuth provider
    /// </summary>
    internal interface IOauthProvider
    {
        /// <summary>
        /// Authorizes the specified model.
        /// </summary>
        /// <param name="model">The model.</param>
        dynamic Authorize(ProviderAndAccessToken model);
    }
}