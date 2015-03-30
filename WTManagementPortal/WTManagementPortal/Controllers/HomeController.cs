using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WTManagementPortal.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = "Modify this template to jump-start your ASP.NET MVC application.";

            // problem exists here sometimes because when we start the application the User.Identity.IsAuthenticated is still true
            // unless I restart the browser.
             if(User.Identity.IsAuthenticated)
             {
                //TODO: check if user has given post registration details
                 if (System.Web.HttpContext.Current.Session["userInRegProcess"] != null)
                 {
                     return RedirectToAction("postRegister", "Account");
                 }
                
                
             }
             
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = " - File Archiver";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}
