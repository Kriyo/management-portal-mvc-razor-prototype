using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WTManagementPortal.ViewModels
{
    public class DashboardGrid
    {  
        public AllAgent agentList { get; set; }
        public IEnumerable<AllWatchPoint> agentDetails { get; set; }
        public int TotalAgent { get; set; }
        public int AliveAgent { get; set; }
        public int DeadAgent { get; set; }
    }   
}