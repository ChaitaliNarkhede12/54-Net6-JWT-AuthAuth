namespace Net6JWTAuthCustomMiddleware.Shared
{
    public interface IJwtUtils
    {
        public string GenerateToken(User user);
        public User ValidateToken(string token);
    }
}
