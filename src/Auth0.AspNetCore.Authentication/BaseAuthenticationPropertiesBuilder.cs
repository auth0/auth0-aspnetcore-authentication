﻿using Microsoft.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Authentication
{
    public abstract class BaseAuthenticationPropertiesBuilder
    {
        protected readonly AuthenticationProperties AuthenticationProperties;

        protected BaseAuthenticationPropertiesBuilder(AuthenticationProperties? properties = null)
        {
            AuthenticationProperties = properties ?? new AuthenticationProperties();
            AuthenticationProperties.RedirectUri ??= "/";
        }
    }
}