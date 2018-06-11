namespace RedTop.Security.OAuthService.Controllers
{
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OAuth;
    using Ninject;
    using RedTop.Security.OAuthService.Identity;
    using RedTop.Security.OAuthService.Providers;
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using System.Web.Http;

    [RoutePrefix("account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ServiceUserManager _userManager;

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        public AccountController()
        {
        }

        public AccountController(
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            AccessTokenFormat = accessTokenFormat;
        }

        public ServiceUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ServiceUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        // GET api/Account/UserInfo
        [Route("userInfo")]
        [HttpGet]
        public UserInfoModel GetUserInfo()
        {
            UserInfoModel userInfo = new UserInfoModel
            {
                Email = User.Identity.GetUserName(),
                UserId = User.Identity.GetUserId(),
            };

            return userInfo;
        }

        // POST api/Account/Logout
        [Route("logout")]
        [HttpPost]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // POST api/Account/ChangePassword
        [Route("password/change")]
        [HttpPost]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("password/set")]
        [HttpPost]
        public async Task<IHttpActionResult> SetPassword(SetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("login/remove")]
        [HttpDelete]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("register")]
        public async Task<IHttpActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ServiceUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                if (result.Errors != null && result.Errors.Where(error => error.Contains("is already taken")).Any())
                {
                    return BadRequest($"Email {model.Email} is already taken");
                }
                return GetErrorResult(result);
            }

            return Created(new Uri($"{Request.RequestUri.GetLeftPart(UriPartial.Authority)}/token"), new { Email = model.Email });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("external/register")]
        public async Task<IHttpActionResult> RegisterUsingExternalProvider(ProviderAndAccessToken model)
        {
            ExternalProvider externalProvider;

            if (!Enum.TryParse<ExternalProvider>(model.Provider, out externalProvider))
            {
                return BadRequest($"Invalid provider : {model.Provider}");
            }
            dynamic userData = AuthorizeByExternalProvider(model, externalProvider);

            ServiceUser user = await UserManager.FindAsync(new UserLoginInfo(model.Provider, userData.id));

            if (user != null || (await UserManager.FindByEmailAsync(userData.userName) != null || await UserManager.FindByNameAsync(userData.userName) != null))
            {
                return BadRequest($"{userData.userName} is already registered");
            }

            user = new ServiceUser() { UserName = userData.userName, Email = userData.userName };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, new UserLoginInfo(model.Provider, userData.id));
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            user = await UserManager.FindAsync(new UserLoginInfo(model.Provider, userData.id));

            return Ok(new { access_token = getServiceAccessToken(user) });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("external/login")]
        public async Task<IHttpActionResult> LoginUsingExternalProvider(ProviderAndAccessToken model)
        {
            ExternalProvider externalProvider;
            if (!Enum.TryParse<ExternalProvider>(model.Provider, out externalProvider))
            {
                return BadRequest($"Invalid provider : {model.Provider}");
            }

            dynamic userData = AuthorizeByExternalProvider(model, externalProvider);

            ServiceUser user = await UserManager.FindAsync(new UserLoginInfo(model.Provider, userData.id));

            return Ok(new { access_token = getServiceAccessToken(user) });
        }

        private dynamic AuthorizeByExternalProvider(ProviderAndAccessToken model, ExternalProvider externalProvider)
        {
            IKernel kernel = Infrastructure.DependencyResolver.GetKernel();
            IOauthProvider oauthProvider = kernel.Get<IOauthProvider>(externalProvider.ToString());
            try
            {
                dynamic userData = oauthProvider.Authorize(model);
                userData.userName = userData.userData.userName.Replace(" ", "");
                if (!userData.userName.ToString().Contains("@")) //google already adds @gmail.com to returned data so this should be optional.
                    userData.userName = userData.userName + "@" + externalProvider.ToString() + ".com";
                return userData;
            }
            catch (Exception ex)
            {
                HttpContent contentPost = new StringContent("Facebook : " + ex.Message, Encoding.UTF8, "application/text");
                var msg = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = contentPost
                };
                throw new HttpResponseException(msg);
            }
        }

        private async Task<string> getServiceAccessToken(ServiceUser user)
        {
            var identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddDays(30)
            };
            ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                   OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                CookieAuthenticationDefaults.AuthenticationType);

            AuthenticationProperties properties = ServiceOAuthProvider.CreateProperties(user.UserName);
            Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);

            identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));

            identity.AddClaim(new Claim("role", "user"));
            var ticket = new AuthenticationTicket(identity, props);

            return OAuthConfig.OAuthOptions.AccessTokenFormat.Protect(ticket);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        #endregion Helpers
    }
}