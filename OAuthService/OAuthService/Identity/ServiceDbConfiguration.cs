namespace RedTop.Security.OAuthService.Identity
{
    using System.Data.Common;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.SqlClient;

    public class ServiceDbConfiguration : DbConfiguration
    {
        public ServiceDbConfiguration()
        {
            SetDatabaseInitializer<ServiceDbContext>(null);
        }

        public class MyManifestTokenResolver : IManifestTokenResolver
        {
            private readonly IManifestTokenResolver _defaultResolver = new DefaultManifestTokenResolver();

            public string ResolveManifestToken(DbConnection connection)
            {
                var sqlConn = connection as SqlConnection;
                if (sqlConn != null && sqlConn.DataSource == @".\SQLEXPRESS")
                {
                    return "2008";
                }
                else
                {
                    return _defaultResolver.ResolveManifestToken(connection);
                }
            }
        }

    }
}
