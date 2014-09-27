/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using BrockAllen.MembershipReboot;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Thinktecture.IdentityModel.Extensions;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Authentication;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;
using ClaimHelper = BrockAllen.MembershipReboot.ClaimsExtensions;
using Thinktecture.IdentityServer.Core.Plumbing;

namespace Thinktecture.IdentityServer.MembershipReboot
{
    public class MembershipRebootUserService<TAccount> : IUserService, IDisposable
        where TAccount : UserAccount
    {
        protected readonly UserAccountService<TAccount> userAccountService;
        IDisposable cleanup;
        public MembershipRebootUserService(UserAccountService<TAccount> userAccountService, IDisposable cleanup)
        {
            if (userAccountService == null) throw new ArgumentNullException("userAccountService");

            this.userAccountService = userAccountService;
            this.cleanup = cleanup;
        }

        public virtual void Dispose()
        {
            if (this.cleanup != null)
            {
                this.cleanup.Dispose();
                this.cleanup = null;
            }
        }

        public virtual Task<IEnumerable<Claim>> GetProfileDataAsync(
            ClaimsPrincipal subject,
            IEnumerable<string> requestedClaimTypes = null)
        {
            var acct = userAccountService.GetByID(subject.GetSubjectId().ToGuid());
            if (acct == null)
            {
                throw new ArgumentException("Invalid subject identifier");
            }

            var claims = GetClaimsFromAccount(acct);
            if (requestedClaimTypes != null)
            {
                claims = claims.Where(x => requestedClaimTypes.Contains(x.Type));
            }

            return Task.FromResult<IEnumerable<Claim>>(claims);
        }

        protected virtual IEnumerable<Claim> GetClaimsFromAccount(TAccount account)
        {
            var claims = new List<Claim>{
                new Claim(Constants.ClaimTypes.Subject, account.ID.ToString("D")),
                new Claim(Constants.ClaimTypes.UpdatedAt, account.LastUpdated.ToEpochTime().ToString()),
                new Claim(MembershipRebootConstants.ClaimTypes.Tenant, account.Tenant),
            };

            if (!String.IsNullOrWhiteSpace(account.Email))
            {
                claims.Add(new Claim(Constants.ClaimTypes.Email, account.Email));
                claims.Add(new Claim(Constants.ClaimTypes.EmailVerified, account.IsAccountVerified ? "true" : "false"));
            }

            if (!String.IsNullOrWhiteSpace(account.MobilePhoneNumber))
            {
                claims.Add(new Claim(Constants.ClaimTypes.PhoneNumber, account.MobilePhoneNumber));
                claims.Add(new Claim(Constants.ClaimTypes.PhoneNumberVerified, !String.IsNullOrWhiteSpace(account.MobilePhoneNumber) ? "true" : "false"));
            }

            claims.AddRange(account.Claims.Select(x => new Claim(x.Type, x.Value)));
            //claims.AddRange(userAccountService.MapClaims(account));

            return claims;
        }

        protected virtual string GetDisplayNameForAccount(Guid accountID)
        {
            var acct = userAccountService.GetByID(accountID);

            var name = acct.Claims.Where(x=>x.Type==Constants.ClaimTypes.Name).Select(x=>x.Value).FirstOrDefault();
            if (name == null) name = acct.Claims.Where(x => x.Type == ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
            if (name == null) name = acct.Username;

            return name;
        }

        public virtual Task<AuthenticateResult> AuthenticateLocalAsync(string username, string password, SignInMessage message)
        {
            TAccount account;
            if (userAccountService.Authenticate(username, password, out account))
            {
                var subject = account.ID.ToString("D");
                var name = GetDisplayNameForAccount(account.ID);

                //if (account.RequiresTwoFactorAuthCodeToSignIn())
                //{
                //    return new AuthenticateResult("/core/account/twofactor", subject, name);
                //}
                //if (account.RequiresTwoFactorCertificateToSignIn())
                //{
                //    return new AuthenticateResult("/core/account/certificate", subject, name);
                //}
                //if (account.RequiresPasswordReset || userAccountService.IsPasswordExpired(account))
                //{
                //    return new AuthenticateResult("/core/account/changepassword", subject, name);
                //}

                var p = IdentityServerPrincipal.Create(subject, name);
                return Task.FromResult(new AuthenticateResult(p));
            }

            if (account != null)
            {
                if (!account.IsLoginAllowed)
                {
                    return Task.FromResult(new AuthenticateResult("Account is not allowed to login"));
                }

                if (account.IsAccountClosed)
                {
                    return Task.FromResult(new AuthenticateResult("Account is closed"));
                }
            }

            return Task.FromResult<AuthenticateResult>(null);
        }

        public virtual async Task<AuthenticateResult> AuthenticateExternalAsync(ExternalIdentity externalUser)
        {
            if (externalUser == null)
            {
                throw new ArgumentNullException("externalUser");
            }

            try
            {
                var acct = this.userAccountService.GetByLinkedAccount(externalUser.Provider.Name, externalUser.ProviderId);
                if (acct == null)
                {
                    return await ProcessNewExternalAccountAsync(externalUser.Provider.Name, externalUser.ProviderId, externalUser.Claims);
                }
                else
                {
                    return await ProcessExistingExternalAccountAsync(acct.ID, externalUser.Provider.Name, externalUser.ProviderId, externalUser.Claims);
                }
            }
            catch (ValidationException ex)
            {
                return new AuthenticateResult(ex.Message);
            }
        }

        protected virtual async Task<AuthenticateResult> ProcessNewExternalAccountAsync(string provider, string providerId, IEnumerable<Claim> claims)
        {
            var acct = userAccountService.CreateAccount(Guid.NewGuid().ToString("N"), null, null);
            userAccountService.AddOrUpdateLinkedAccount(acct, provider, providerId);

            var result = await AccountCreatedFromExternalProviderAsync(acct.ID, provider, providerId, claims);
            if (result != null) return result;

            return await SignInFromExternalProviderAsync(acct.ID, provider);
        }

        protected virtual async Task<AuthenticateResult> AccountCreatedFromExternalProviderAsync(Guid accountID, string provider, string providerId, IEnumerable<Claim> claims)
        {
            SetAccountEmail(accountID, ref claims);
            SetAccountPhone(accountID, ref claims);

            return await UpdateAccountFromExternalClaimsAsync(accountID, provider, providerId, claims);
        }

        protected virtual Task<AuthenticateResult> SignInFromExternalProviderAsync(Guid accountID, string provider)
        {
            var p = IdentityServerPrincipal.Create(
                accountID.ToString("D"),
                GetDisplayNameForAccount(accountID),
                IdentityServer.Core.Constants.AuthenticationMethods.External,
                provider
            );
            return Task.FromResult(new AuthenticateResult(p));
        }

        protected virtual Task<AuthenticateResult> UpdateAccountFromExternalClaimsAsync(Guid accountID, string provider, string providerId, IEnumerable<Claim> claims)
        {
            userAccountService.AddClaims(accountID, new UserClaimCollection(claims));
            return Task.FromResult<AuthenticateResult>(null);
        }

        protected virtual async Task<AuthenticateResult> ProcessExistingExternalAccountAsync(Guid accountID, string provider, string providerId, IEnumerable<Claim> claims)
        {
            return await SignInFromExternalProviderAsync(accountID, provider);
        }

        protected virtual void SetAccountEmail(Guid accountID, ref IEnumerable<Claim> claims)
        {
            var email = ClaimHelper.GetValue(claims, Constants.ClaimTypes.Email);
            if (email != null)
            {
                var acct = userAccountService.GetByID(accountID);
                if (acct.Email == null)
                {
                    try
                    {
                        var email_verified = ClaimHelper.GetValue(claims, Constants.ClaimTypes.EmailVerified);
                        if (email_verified != null && email_verified == "true")
                        {
                            userAccountService.SetConfirmedEmail(acct.ID, email);
                        }
                        else
                        {
                            userAccountService.ChangeEmailRequest(acct.ID, email);
                        }

                        var emailClaims = new string[] { Constants.ClaimTypes.Email, Constants.ClaimTypes.EmailVerified };
                        claims = claims.Where(x => !emailClaims.Contains(x.Type));
                    }
                    catch (ValidationException)
                    {
                        // presumably the email is already associated with another account
                        // so eat the validation exception and let the claim pass thru
                    }
                }
            }
        }

        protected virtual void SetAccountPhone(Guid accountID, ref IEnumerable<Claim> claims)
        {
            var phone = ClaimHelper.GetValue(claims, Constants.ClaimTypes.PhoneNumber);
            if (phone != null)
            {
                var acct = userAccountService.GetByID(accountID);
                if (acct.MobilePhoneNumber == null)
                {
                    try
                    {
                        var phone_verified = ClaimHelper.GetValue(claims, Constants.ClaimTypes.PhoneNumberVerified);
                        if (phone_verified != null && phone_verified == "true")
                        {
                            userAccountService.SetConfirmedMobilePhone(acct.ID, phone);
                        }
                        else
                        {
                            userAccountService.ChangeMobilePhoneRequest(acct.ID, phone);
                        }

                        var phoneClaims = new string[] { Constants.ClaimTypes.PhoneNumber, Constants.ClaimTypes.PhoneNumberVerified };
                        claims = claims.Where(x => !phoneClaims.Contains(x.Type));
                    }
                    catch (ValidationException)
                    {
                        // presumably the phone is already associated with another account
                        // so eat the validation exception and let the claim pass thru
                    }
                }
            }
        }

        public Task<bool> IsActive(ClaimsPrincipal subject)
        {
            var acct = userAccountService.GetByID(subject.GetSubjectId().ToGuid());
            if (acct == null)
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(!acct.IsAccountClosed && acct.IsLoginAllowed);
        }
    }
}