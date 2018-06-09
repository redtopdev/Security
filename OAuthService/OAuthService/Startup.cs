using Microsoft.Owin;

[assembly: OwinStartup(typeof(RedTop.Security.OAuthService.Startup))]

namespace RedTop.Security.OAuthService
{
    using Ninject.Web.Common.OwinHost;
    using Owin;

    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            OAuthConfig.Configure(app);
            app.UseNinjectMiddleware(Infrastructure.DependencyResolver.GetKernel);
        }
    }
}
