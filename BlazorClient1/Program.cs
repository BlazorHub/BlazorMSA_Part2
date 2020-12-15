using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

namespace BlazorClient1 {
  public class Program {
    public static async Task Main(string[] args) {
      var builder = WebAssemblyHostBuilder.CreateDefault(args);
      builder.RootComponents.Add<App>("#app");

      builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

      builder.Services.AddOidcAuthentication(options => {
        // load Oidc options for the Identity Server authentication.
        builder.Configuration.Bind("oidc", options.ProviderOptions);
        // get the roles from the claim named "role" 
        options.UserOptions.RoleClaim = "role";
      })
        // load the roles inside the claim array "role" ("role": ["Admin", "User, ...]) 
      .AddAccountClaimsPrincipalFactory<CustomUserFactory>();

      builder.Services.AddAuthorizationCore(options =>
      {
        options.AddPolicy("WebApi_List", policy => policy.RequireClaim("WebApi1.List", "true"));
        options.AddPolicy("WebApi_Update", policy => policy.RequireClaim("WebApi1.Update", "true"));
        options.AddPolicy("WebApi_Delete", policy => policy.RequireClaim("WebApi1.Delete", "true"));
        options.AddPolicy("ComplexPolicy", policy => policy
            .RequireClaim("WebApi1.Delete", "true")
            .RequireClaim("WebApi1.Update", "true")
            .RequireRole("BlazorClient1_Admin", "BlazorClient1_User")
        );
        options.AddPolicy("MoreComplexPolicy", policy => policy
          .RequireAssertion(context => 
               context.User.HasClaim(claim => claim.Type == "WebApi1.Delete" || claim.Type == "WebApi1.Delete") ||
               context.User.IsInRole("BlazorClient1_Admin")
          )
        ); 
      });

      await builder.Build().RunAsync();
    }
  }
}
