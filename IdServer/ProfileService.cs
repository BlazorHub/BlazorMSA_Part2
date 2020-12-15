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

namespace IdServer {



  public class ProfileService : IProfileService {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsFactory;

    public ProfileService(
      UserManager<ApplicationUser> userManager,
      RoleManager<IdentityRole> roleManager,
      IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory) {
      _userManager = userManager;
      _roleManager = roleManager;
      _claimsFactory = claimsFactory;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context) {
      // Read the <ApplicationUser> from the DB
      var user = await _userManager.GetUserAsync(context.Subject);
      // Get the ClainsPrincipal from the user
      var principal = await _claimsFactory.CreateAsync(user);
      // All the user claims + roles in claim "role"
      var nameClaims = principal.Claims.ToList();

      //cet requested claims by the client
      var reqclaims = context.RequestedClaimTypes;
      //filter out only the requested claims
      var retclaims = nameClaims.Where(claim => reqclaims.Contains(claim.Type)).ToList();
      //return only the requested claims
      context.IssuedClaims.AddRange(retclaims);

      // get the user roles list
      var stringRoles = await _userManager.GetRolesAsync(user);
      // transform the roles to an array of claims
      var rolesAsClaims2 = stringRoles.Select(role => new Claim(JwtClaimTypes.Role, role));
      // return the user roles in claims named "role"
      // they will be concatenated in this way "role:  ["Admin", "User",...]
      context.IssuedClaims.AddRange(rolesAsClaims2.ToArray());

      // get the IdentityRoles
      var roles = _roleManager.Roles.Where(r => stringRoles.Contains(r.Name));
      // add the roleclaims associated to the role
      var roleClimesToAdd = new List<Claim>();
      foreach (var r in roles) {
        //get role claims
        var roleClaims = await _roleManager.GetClaimsAsync(r);
        //add the RoleClaim and avoid duplicates
        foreach (var rc in roleClaims) {
          if (roleClaims.Where(i => i.Type == rc.Type && i.Value == rc.Value).Any()) {
            roleClimesToAdd.Add(rc);
          }
        }
        context.IssuedClaims.AddRange(roleClimesToAdd);
      }
    }

    public async Task IsActiveAsync(IsActiveContext context) {
      var user = await _userManager.GetUserAsync(context.Subject);
      context.IsActive = (user != null) && user.LockoutEnabled;
    }


  }
}
