using Ninject;
using RedTop.Security.OAuthService.Providers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedTop.Security.OAuthService.Infrastructure
{

    /// <summary>
    ///Ninject dependency resolver
    /// </summary>
    public static class DependencyResolver
    {
        /// <summary>
        /// The kernel
        /// </summary>
        private static IKernel kernel;

        /// <summary>
        /// Gets the kernel.
        /// </summary>
        /// <returns></returns>
        public static IKernel GetKernel()
        {
            if (null == kernel) //singleton pattern
            {
                kernel = new StandardKernel();
                AddBindings();
            }
            return kernel;
        }

        /// <summary>
        /// Adds the bindings here.
        /// </summary>
        private static void AddBindings()
        {
            kernel.Bind<IOauthProvider>().To<FacebookProvider>().Named(ExternalProvider.facebook.ToString());
        }
    }
}
