using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WTManagementPortal.ViewModels;

namespace WTManagementPortal.Controllers
{
    public class DashboardController : Controller
    {
        
        public ActionResult Main()
        {
            var agentCount = new DashboardGrid();
            using (WTPortalEntities wtp = new WTPortalEntities())
            {                
                agentCount.TotalAgent = wtp.AllAgents.OrderByDescending(a => a.AgentID).Count(); // All Agents
                agentCount.AliveAgent = wtp.AllAgents.Where(a => a.AgentAlive == "1").Count();  // Alive Agents
                agentCount.DeadAgent = wtp.AllAgents.Where(a => a.AgentAlive == "0").Count();  // Unresponding Agents
            }
            return View(agentCount);
        }

        // All Agents
        public ActionResult _allAgents()
        {
            List<DashboardGrid> allAgents = new List<DashboardGrid>();     
            using (WTPortalEntities wtp = new WTPortalEntities())
            {
                // All Agents
                var ag = wtp.AllAgents.OrderByDescending(a => a.AgentID);
                foreach (var i in ag)
                {
                    // All Watchpoints for each Agent
                    var aw = wtp.AllWatchPoints.Where(a => a.AgentID.Equals(i.AgentID)).ToList();
                    allAgents.Add(new DashboardGrid { agentList = i, agentDetails = aw });
                }
            }
            return PartialView(allAgents);
        }

        // Populate the Responding Agents /w Nested WPs
        public ActionResult _AliveAgents()
        {
            List<DashboardGrid> allAgents = new List<DashboardGrid>();
            using (WTPortalEntities wtp = new WTPortalEntities())
            {
                // All Watchpoints for responding Agents
                var ag = wtp.AllAgents.Where(a => a.AgentAlive == "1");
                foreach (var i in ag)
                {
                    var aw = wtp.AllWatchPoints.Where(a => a.AgentID == i.AgentID).ToList();
                    allAgents.Add(new DashboardGrid { agentList = i, agentDetails = aw });
                }
            }
            return PartialView(allAgents);
        }  

        // Non responding Agents
        public ActionResult _NoAgents()
        {
            List<DashboardGrid> allAgents = new List<DashboardGrid>();            
            using (WTPortalEntities wtp = new WTPortalEntities())
            {
                // All Watchpoints for nonresponding Agents
                var ag = wtp.AllAgents.Where(a => a.AgentAlive == "0");
                foreach (var i in ag)
                {
                    var aw = wtp.AllWatchPoints.Where(a => a.AgentID == i.AgentID).ToList();
                    allAgents.Add(new DashboardGrid { agentList = i, agentDetails = aw });
                }
            }
            return PartialView(allAgents);
        }
    }    
}
