using System;

namespace Auth0.AspNetCore.Mvc
{
    internal class IdTokenValidationException : Exception
    {
        public IdTokenValidationException(string message): base(message)
        {

        }
    }
}
