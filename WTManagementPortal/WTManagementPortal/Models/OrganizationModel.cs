using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WTManagementPortal.Models
{
    public class OrganizationModel
    {
        public String orgName { get; set; }

        public String emailAddr { get; set; }

        public String username { get; set; }

        public OrganizationModel()
        {

        }
    }

    public class PostRegistrationModel
    {

        public String newPassword { get; set; }

        public String confirmPassword { get; set; }

        public String passwordQuestion { get; set; }

        public String passwordAnswer { get; set; }

        public PostRegistrationModel()
        {

        }
    }

    public class TenantDetailsModel
    {

        public String phoneNumber { get; set; }

        public String faxNumber { get; set; }

        public String addressLine1 { get; set; }

        public String addressLine2 { get; set; }

        public String city { get; set; }

        public String state { get; set; }
        
        public String country { get; set; }

        public String zipcode { get; set; }

        public TenantDetailsModel()
        {

        }
    }


}