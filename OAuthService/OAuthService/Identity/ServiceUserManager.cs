namespace RedTop.Security.OAuthService.Identity
{
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin;

    public class ServiceUserManager : UserManager<ServiceUser>
    {
        private ServiceUserManager(IUserStore<ServiceUser> store)
            : base(store)
        {
        }

        public static ServiceUserManager Create(IdentityFactoryOptions<ServiceUserManager> options, IOwinContext context)
        {
            var manager = new ServiceUserManager(new UserStore<ServiceUser>(context.Get<ServiceDbContext>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ServiceUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 4,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<ServiceUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }
    
}
