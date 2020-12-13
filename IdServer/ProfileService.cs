using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdServer.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdServer
{



  public class ProfileService : IProfileService
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsFactory;

    public ProfileService(
      UserManager<ApplicationUser> userManager, 
      IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory)
    {
      _userManager = userManager;
      _claimsFactory = claimsFactory;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
      // Read the <ApplicationUser> from the DB
      var user = await _userManager.GetUserAsync(context.Subject);
      // Get the ClainsPrincipal from the user
      var principal = await _claimsFactory.CreateAsync(user);
      // All the user claims
      var nameClaims = principal.Claims.ToList();

      //requested claims by the client
      var reqclaims = context.RequestedClaimTypes;
      //filter only the requested claims
      var retclaims = nameClaims.Where(claim => reqclaims.Contains(claim.Type)).ToList();

      //return only the requested claims
      context.IssuedClaims.AddRange(retclaims);

      // Get the user roles as claims
      var roleClaims = context.Subject.FindAll(JwtClaimTypes.Role);
      // Add the user roles as claim role:  ["Admin", "User",...]
      context.IssuedClaims.AddRange(roleClaims);

      // Get the user roles (just for debug)
      //var roles = await _userManager.GetRolesAsync(user);
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
      var user = await _userManager.GetUserAsync(context.Subject);
      context.IsActive = (user != null) && user.LockoutEnabled;
    }
  }

}
