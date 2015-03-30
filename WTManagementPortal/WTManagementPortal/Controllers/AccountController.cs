using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.Mvc;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Protocols;
using ComponentSpace.SAML2.Profiles.SingleLogout;
using ComponentSpace.SAML2.Bindings;
using AspiraCloud.Configuration;
using System.Web.Routing;
using System.Security;
using System.Threading;
using System.Web.Configuration;
using System.Diagnostics;
using System.Text;
using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Profiles.ArtifactResolution;
using ComponentSpace.SAML2.Profiles.SSOBrowser;
using AspiraCloud.Providers.Session;
using AspiraCloud.Shared.Certificates;
using System.Configuration;
using System.IO;
using WTManagementPortal.Models;
using AspiraCloud.ServiceProxy.Common;



namespace MarketPlace.Controllers
{
    public class AccountController : Controller
    {
        

        public ActionResult Login()
        {
            return RedirectToAction("SAMLLogOn", "SAML");
        }

  
      

        [Authorize]
        public ActionResult postRegister()
        {
            return View();
        }



   
    }
}