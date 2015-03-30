using System.Web;
using System.Web.Optimization;

namespace WTManagementPortal
{
    public class BundleConfig
    {
        // For more information on Bundling, visit http://go.microsoft.com/fwlink/?LinkId=254725
        public static void RegisterBundles(BundleCollection bundles)
        {
            bundles.Add(new ScriptBundle("~/bundles/jquery").Include(
                        "~/Scripts/jquery-1.8.2.js"));

            bundles.Add(new ScriptBundle("~/bundles/bootstrapjs").Include(
                        "~/Scripts/bootstrap.min.js"));

            bundles.Add(new ScriptBundle("~/bundles/charts").Include(
                        "~/Scripts/charts-min.js"));

            bundles.Add(new ScriptBundle("~/bundles/jqueryval").Include(
                        "~/Scripts/jquery.unobtrusive*",
                        "~/Scripts/jquery.validate*"));

            bundles.Add(new ScriptBundle("~/bundles/knockout").Include(
                        "~/Scripts/knockout-2.2.0.js"));

            // Use the development version of Modernizr to develop with and learn from. Then, when you're
            // ready for production, use the build tool at http://modernizr.com to pick only the tests you need.
            bundles.Add(new ScriptBundle("~/bundles/modernizr").Include(
                        "~/Scripts/modernizr-*"));

            bundles.Add(new ScriptBundle("~/bundles/dashboard").Include(
                        "~/Scripts/dashboard.js"));

            bundles.Add(new LessBundle("~/Content/less").Include("~/Content/*.less"));

            bundles.Add(new StyleBundle("~/Content/bootstrapcss").Include("~/Content/bootstrap.css"));
            
            bundles.Add(new StyleBundle("~/Content/bootstraprcss").Include("~/Content/bootstrap-responsive.css"));

            bundles.Add(new StyleBundle("~/Content/iconicbootstrap").Include("~/Content/open-iconic-bootstrap.less"));

            bundles.Add(new StyleBundle("~/Content/iconic").Include("~/Content/open-iconic.less"));

            bundles.Add(new StyleBundle("~/Content/sitecss").Include("~/Content/Site.css"));

        }
    }
}