using System.Net;

namespace Net6JWTAuthCustomMiddleware.Shared
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, IJwtUtils jwtUtils)
        {
            if (context.Request.Path.Value == "/api/Login")
            {
                await _next(context);
            }
            else
            {
                var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

                var userFromToken = jwtUtils.ValidateToken(token);
                if (userFromToken != null)
                {
                    User user = new User()
                    {
                        Id = userFromToken.Id,
                        UserName = userFromToken.Name,
                        Name = userFromToken.Name,
                        Roles = userFromToken.Roles
                    };

                    context.Items["User"] = user;
                }
               
                await _next(context);
            }
        }
    }
}

