using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using BrockAllen.MembershipReboot.Relational;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Thinktecture.IdentityManager;
using Thinktecture.IdentityManager.MembershipReboot;

namespace Thinktecture.IdentityManager.Host
{
    public class MembershipRebootIdentityManagerFactory
    {
        static MembershipRebootConfiguration<RelationalUserAccount> config;
        static MembershipRebootIdentityManagerFactory()
        {
            System.Data.Entity.Database.SetInitializer(new System.Data.Entity.MigrateDatabaseToLatestVersion<DefaultMembershipRebootDatabase, BrockAllen.MembershipReboot.Ef.Migrations.Configuration>());

            config = new MembershipRebootConfiguration<RelationalUserAccount>();
            config.PasswordHashingIterationCount = 10000;
            config.RequireAccountVerification = false;
        }

        string connString;
        public MembershipRebootIdentityManagerFactory(string connString)
        {
            this.connString = connString;
        }
        
        public IIdentityManagerService Create()
        {
            var userrepo = new DefaultUserAccountRepository(this.connString);
            userrepo.QueryFilter = RelationalUserAccountQuery.Filter;
            userrepo.QuerySort = RelationalUserAccountQuery.Sort;
            var usersvc = new UserAccountService<RelationalUserAccount>(config, userrepo);
            
            var grprepo = new DefaultGroupRepository(this.connString);
            var grpsvc = new GroupService<RelationalGroup>(grprepo);
            
            var svc = new MembershipRebootIdentityManagerService<RelationalUserAccount, RelationalGroup>(usersvc, userrepo, grpsvc, grprepo);
            return new DisposableIdentityManagerService(svc, userrepo);
        }
    }
}