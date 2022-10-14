using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTAPI.Controllers
{
    [ApiController]
    public class ProtectedController : Controller
    {
        private readonly IHttpContextAccessor _contextAccessor;
        public ProtectedController(IHttpContextAccessor httpContextAccessor)
        {
            _contextAccessor = httpContextAccessor;
        }

        [HttpGet]
        [Authorize]
        [Route("/api/protectedforcommonusers")]
        public IActionResult GetProtectedData()
        {
            return Ok("Hello world from protected controller.");
        }

        [HttpGet]
        [Authorize(Roles = "Administrator")]
        [Route("/api/protectedforadministrators")]
        public IActionResult GetProtectedDataForAdmin()
        {
            return Ok("Hello admin!");
        }

        [HttpGet]
        [Authorize]
        [Route("/api/redirecttorole")]
        public IActionResult RedirectRole()
        {
            if (User.IsInRole("Common"))
                return RedirectToAction("CommonDashboard");
            else if(User.IsInRole("Admin"))
                return RedirectToAction("AdminDashboard");
            
            return BadRequest("You are not logged in!");
        }

        [HttpGet]
        [Authorize]
        [Route("/api/commondashboard")]
        public IActionResult CommonDashboard()
        {
            return Ok("Welcome to your dashboard, common!");
        }

        [HttpGet]
        [Authorize(Roles = "Administrator")]
        [Route("/api/admindashboard")]
        public IActionResult AdminDashboard()
        {
            return Ok("Welcome to your dashboard, admin!");
        }
    }
}