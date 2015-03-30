using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace WTManagementPortal
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");


            //SAML Custom Route.
            routes.MapRoute(
               name: "spAssertionURL",
               url: "SAML/AssertionConsumerService.aspx",
               defaults: new { controller = "SAML", action = "AssertionConsumerService", id = UrlParameter.Optional }
           );

            routes.MapRoute(
                name: "spLogoutURL",
                url: "SAML/SingleLogoutService.aspx",
                defaults: new { controller = "SAML", action = "SingleLogoutService", id = UrlParameter.Optional }
            );

            routes.MapRoute(
               name: "spArtifactResponderURL",
               url: "SAML/ArtifactResponder.aspx",
               defaults: new { controller = "SAML", action = "ArtifactResponder", id = UrlParameter.Optional }
           );

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );
        }
    }
}