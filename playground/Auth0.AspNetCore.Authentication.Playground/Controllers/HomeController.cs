using Auth0.AspNetCore.Authentication.Playground.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Diagnostics;

namespace Auth0.AspNetCore.Authentication.Playground.Controllers
{
    public class HomeController : Controller
    {
        private readonly Auth0WebAppOptions _snapshotOptions;
        public HomeController(IOptionsSnapshot<Auth0WebAppOptions> namedOptionsAccessor)
        {
            _snapshotOptions = namedOptionsAccessor.Get(Auth0Constants.AuthenticationScheme);
        }
        public IActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        public IActionResult Admin()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
