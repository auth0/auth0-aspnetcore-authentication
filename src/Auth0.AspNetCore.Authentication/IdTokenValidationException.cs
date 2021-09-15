using System;

namespace Auth0.AspNetCore.Authentication
{
    internal class IdTokenValidationException : Exception
    {
        public IdTokenValidationException(string message): base(message)
        {

        }
    }
}
