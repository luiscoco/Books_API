using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTRefreshToken.NET6._0.Auth;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using BookStoreApi.Auth;

namespace BookStoreApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private RoleManager<ApplicationRole> roleManager;
        private SignInManager<ApplicationUser> signInManager;
        private readonly IConfiguration configuration;

        public AuthenticateController(UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
             SignInManager<ApplicationUser> signInManager,
             IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
        }

        [HttpPost]
        [Route("registerUser")]
        public async Task<IActionResult> RegisterUser(User user)
        {
            var userExists = await this.userManager.FindByNameAsync(user.Name);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser appUser = new ApplicationUser
            {
                UserName = user.Name,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = user.Email
            };

            var result = await this.userManager.CreateAsync(appUser, user.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await this.roleManager.RoleExistsAsync(UserRoles.Admin))
                await this.roleManager.CreateAsync(new ApplicationRole() { Name = UserRoles.Admin });
            if (!await this.roleManager.RoleExistsAsync(UserRoles.User))
                await this.roleManager.CreateAsync(new ApplicationRole() { Name = UserRoles.User });

                if (await this.roleManager.RoleExistsAsync(UserRoles.User))
                {
                await this.userManager.AddToRoleAsync(appUser, UserRoles.User);
                }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("registerAdmin")]
        public async Task<IActionResult> RegisterAdmin(User user)
        {
            var userExists = await this.userManager.FindByNameAsync(user.Name);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser appUser = new ApplicationUser
            {
                UserName = user.Name,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = user.Email
            };

            var result = await this.userManager.CreateAsync(appUser, user.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await this.roleManager.RoleExistsAsync(UserRoles.Admin))
                await this.roleManager.CreateAsync(new ApplicationRole() { Name = UserRoles.Admin });
            if (!await this.roleManager.RoleExistsAsync(UserRoles.User))
                await this.roleManager.CreateAsync(new ApplicationRole() { Name = UserRoles.User });

            if (await this.roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await this.userManager.AddToRoleAsync(appUser, UserRoles.Admin); ;
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            ApplicationUser? appUser = await this.userManager.FindByNameAsync(model.Username);
            if (appUser != null && await this.userManager.CheckPasswordAsync(appUser, model.Password))
            {

                var userRoles = await this.userManager.GetRolesAsync(appUser);

                var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, appUser.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();

                _ = int.TryParse(configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

                appUser.RefreshToken = refreshToken;
                appUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(appUser, model.Password, false, false);
                if (!result.Succeeded)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Login failed" });

                await userManager.UpdateAsync(appUser);

                var tz = TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
                // This would return +1 in winter and +2 in summer when daylight saving is active
                var offset = tz.GetUtcOffset(DateTime.UtcNow);
                DateTime LocalTime = new DateTime();
                LocalTime = token.ValidTo + offset;

                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = LocalTime
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            string username = principal.Identity.Name;

            var user = await this.userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken = CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await this.userManager.UpdateAsync(user);

            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }

        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await this.userManager.FindByNameAsync(username);
            if (user == null) return BadRequest("Invalid user name");

            user.RefreshToken = null;
            await this.userManager.UpdateAsync(user);

            return NoContent();
        }

        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = this.userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await this.userManager.UpdateAsync(user);
            }

            return NoContent();
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            _ = int.TryParse(configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }

    }
}
