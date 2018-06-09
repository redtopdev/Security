
namespace RedTop.Security.OAuthService.Identity
{
    using Microsoft.AspNet.Identity.EntityFramework;
    public class ServiceDbContext : IdentityDbContext<ServiceUser>
    {
        public ServiceDbContext()
           : base("DefaultConnection", throwIfV1Schema: false)
        {
        }

        public static ServiceDbContext Create()
        {
            return new ServiceDbContext();
        }
    }
}
