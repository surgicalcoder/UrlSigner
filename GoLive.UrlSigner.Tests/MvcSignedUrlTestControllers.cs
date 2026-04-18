using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace GoLive.UrlSigner.Tests;

[ApiController]
[Route("mvc")]
public sealed class MvcActionProtectedController : ControllerBase
{
    [RequireSignedUrl]
    [HttpGet("action-protected")]
    public IActionResult ActionProtected() => Ok("action-ok");
}

[ApiController]
[Route("mvc")]
[RequireSignedUrl]
public sealed class MvcControllerProtectedController : ControllerBase
{
    [HttpGet("controller-protected")]
    public IActionResult ControllerProtected() => Ok("controller-ok");
}

