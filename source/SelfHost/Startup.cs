using Owin;
using SelfHost.Config;
using Thinktecture.IdentityServer.Core.Configuration;

namespace SelfHost
{
    internal class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Map("/admin", adminApp =>
            {
                var factory = new Thinktecture.IdentityManager.Host.MembershipRebootIdentityManagerFactory("MembershipReboot");
                adminApp.UseIdentityManager(new Thinktecture.IdentityManager.IdentityManagerConfiguration()
                {
                    IdentityManagerFactory = factory.Create
                });
            });


            var options = new IdentityServerOptions
            {
                IssuerUri = "https://idsrv3.com",
                SiteName = "Thinktecture IdentityServer v3 - UserService-MembershipReboot",
                PublicHostName = "http://localhost:3333",
                SigningCertificate = Certificate.Get(),
                Factory = Factory.Configure("MembershipReboot"),
                CorsPolicy = CorsPolicy.AllowAll
            };

            app.UseIdentityServer(options);
        }
    }
}