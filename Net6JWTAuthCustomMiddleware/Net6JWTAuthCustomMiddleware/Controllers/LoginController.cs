using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Net6JWTAuthCustomMiddleware.Shared;

namespace Net6JWTAuthCustomMiddleware.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        private readonly IJwtUtils _iJwtUtils;

        public LoginController(IConfiguration configuration,
            IJwtUtils iJwtUtils)
        {
            _configuration = configuration;
            _iJwtUtils = iJwtUtils;
        }



        [HttpPost]
        public IActionResult Login(string UserName, string Password)
        {
            User user = new User()
            {
                Id = 1,
                UserName = UserName,
                Password = Password,
                Name = "Admin",
                Email = "",
                Roles = new List<string> { "SuperAdmin" }
                //Roles = new List<string> { "User" }
            };

            var token = _iJwtUtils.GenerateToken(user);
            return Ok(token);
        }

    }
}
