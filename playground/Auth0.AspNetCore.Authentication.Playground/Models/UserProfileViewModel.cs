namespace Auth0.AspNetCore.Authentication.Playground.Models;

public class UserProfileViewModel
{
    public string Name { get; set; }
    public string EmailAddress { get; set; }
    public string ProfileImage { get; set; }
    public string AccessToken { get; set; }
    public string IdToken { get; set; }
    public string RefreshToken { get; set; }
}