using System;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout;

internal class LogoutTokenValidationException : Exception
{
    public LogoutTokenValidationException(string message): base(message)
    {

    }
}