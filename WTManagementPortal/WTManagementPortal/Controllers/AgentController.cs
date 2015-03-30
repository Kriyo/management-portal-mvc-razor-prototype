using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WTManagementPortal.ViewModels;

namespace WTManagementPortal.Controllers
{
    public class AgentController : Controller
    {
        //
        //// GET: /Agent/

        //public ActionResult AgentList()
        //{
        //    List<DashboardGrid> allAgents = new List<DashboardGrid>();

        //    //Data Context for the Agents and nested watchpoints
        //    using (TestAgentDataEntities1 ta = new TestAgentDataEntities1())
        //    {
        //        //All Agents
        //        var ag = ta.Agents.OrderByDescending(a => a.Agent_ID);
        //        foreach (var i in ag)
        //        {
        //            //All Watchpoints for each Agent
        //            var aw = ta.Watches.Where(a => a.Agent_ID.Equals(i.Agent_ID)).ToList();
        //            allAgents.Add(new DashboardGrid { agentList = i, agentDetails = aw });
        //        }
        //    }
        //    return View(allAgents);
        //}

        //public ActionResult ListAgents()
        //{
        //    List<DashboardGrid> allAgents = new List<DashboardGrid>();

        //    //Data Context for the Agents and nested watchpoints
        //    using (TestAgentDataEntities1 ta = new TestAgentDataEntities1())
        //    {
        //        //All Agents
        //        var ag = ta.Agents.OrderByDescending(a => a.Agent_ID);
        //        foreach (var i in ag)
        //        {
        //            //All Watchpoints for each Agent
        //            var aw = ta.Watches.Where(a => a.Agent_ID.Equals(i.Agent_ID)).ToList();
        //            allAgents.Add(new DashboardGrid { agentList = i, agentDetails = aw });
        //        }
        //    }
            
        //    return View(allAgents);
        //}

                     
    }
}
