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
using AspiraCloud.Shared.Enums;

namespace MarketPlace.Controllers
{
    public class SAMLController : Controller
    {
        #region Class_SAML

        // Reference to an instance of the logging class
        private class MessageTypes
        {
            public const string LogoutRequest = "LogoutRequest";
            public const string LogoutResponse = "LogoutResponse";
        }

        //The login can either occur at the identity provider (SSO) or the service provider (local login).
        private class LoginLocations
        {
            public const string IdentityProvider = "IdP";
            public const string ServiceProvider = "SP";
        }


        #endregion

        #region Class_Members

        private log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private IdentityProviderSettings config;

        //The query string parameter identifying whether a request or response message is being sent.
        private const string messageTypeParameter = "message";

        // The query string parameter identifying the IdP to SP binding in use.
        private const string bindingQueryParameter = "binding";

        // The query string parameter indicating an error occurred.
        private const string errorQueryParameter = "error";

        #endregion

        #region SAMLLogOn_Control

        /// <summary>
        /// SAML logon request.
        /// </summary>
        public ActionResult SAMLLogOn(string ReturnURL = null)
        {
            try
            {
                /**********************************************************************
                 *  In the situation where the session has timed out but the user has been
                 *  authenticated then we will redirect to the logoff page.
                 * ********************************************************************/
                if (Session["UserTy"] == null && User.Identity.IsAuthenticated)
                {
                    FormsAuthentication.SignOut();
                    Session.Abandon();

                    return RedirectToAction("SAMLLogOff", "SAML");
                }
                log.Debug(">>SAMLLogOnUserControl.Page_Load");

                // Create the configuration file
                config = (IdentityProviderSettings)System.Configuration.ConfigurationManager.GetSection(SectionNames.IDENTITY_PROVIDER_SECTION);
                if (config == null)
                {
                    throw new Exception("Unable to read configuration section section from web.config");
                }

                // First authenticate the users using SAML 2.0 authentication
                if (SessionManager.Current.DataForAuthMechanism == null)
                {
                    CfWrxAuthenticate(config.IdpssoURL, ReturnURL);
                }
                else
                {
                    CfWrxAuthenticate(config.IdpssoURL, ReturnURL);
                }

            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.Page_Load", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.Page_Load");
            }

            return new EmptyResult();
        }


        // CfWrxAuthenticate
        // This method will 
        //  - Sends a HTML form containing a SAML AuthnRequest message to the browser
        //  - Browser issues an HTTP POST request to send the form  to the Identity Providers
        //    Single Sign On Service.
        public void CfWrxAuthenticate(string idpUrl, string ReturnURL = null)
        {
            try
            {
                log.Debug(">>SAMLLogOnUserControl.CfWrxAuthenticate");

                if (String.IsNullOrEmpty(idpUrl))
                    throw new ArgumentNullException("idpUrl");

                if (config == null)
                {
                    throw new Exception("configuration not initialised correctly");
                }

                RequestLoginAtIdentityProvider(SAMLIdentifiers.BindingURIs.HTTPArtifact, idpUrl, ReturnURL);
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CfWrxAuthenticate", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CfWrxAuthenticate");
            }
        }

        // Create the assertion consumer service URL.
        // Rather than have different endpoints for each binding we use the same endpoint and
        // identify the binding type by a query string parameter.
        private string CreateAssertionConsumerServiceURL()
        {

            try
            {
                log.Debug(">>SAMLLogOnUserControl.CreateAssertionConsumerServiceURL");

                if (config == null)
                {
                    throw new Exception("config is not initialised");
                }

                if (String.IsNullOrEmpty(config.SpAssertionURL) == true)
                {
                    throw new Exception("SP Assertion URL not configured correctly");
                }

                string assertionURL = string.Format("{0}?{1}={2}",
                              CreateAbsoluteURL(config.SpAssertionURL),
                              bindingQueryParameter,
                              HttpUtility.UrlEncode(SAMLIdentifiers.BindingURIs.HTTPArtifact));

                log.InfoFormat("assertion consumer url {0}", assertionURL);

                return assertionURL;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAssertionConsumerServiceURL", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAssertionConsumerServiceURL");
            }
        }

        // Create an authentication request.
        private XmlElement CreateAuthnRequest(string spToIdPBinding)
        {
            try
            {
                log.DebugFormat(">>SAMLLogOnUserControl.CreateAuthnRequest {0}", spToIdPBinding);

                if (config == null)
                {
                    throw new Exception("config is null. Not initialised correctly.");
                }

                if (String.IsNullOrEmpty(config.IdpssoURL) == true)
                {
                    throw new Exception("IdpssoURL is not configured correctly within configuration");
                }

                log.InfoFormat("IdpssoURL = {0}", config.IdpssoURL);

                // Create some URLs to identify the service provider to the identity provider.
                // As we're using the same endpoint for the different bindings, add a query string 
                // parameter to identify the binding.
                string issuerURL = CreateAbsoluteURL("~/");

                XmlElement authnRequestXml;

                string assertionConsumerServiceURL = CreateAssertionConsumerServiceURL();

                // Create the authentication request.
                AuthnRequest authnRequest = new AuthnRequest();
                authnRequest.Destination = config.IdpssoURL;
                authnRequest.Issuer = new Issuer(issuerURL);
                authnRequest.ForceAuthn = false;
                authnRequest.NameIDPolicy = new NameIDPolicy(null, null, true);
                authnRequest.ProtocolBinding = SAMLIdentifiers.BindingURIs.HTTPPost;
                authnRequest.AssertionConsumerServiceURL = assertionConsumerServiceURL;

                //Serialize the authentication request to XML for transmission.
                authnRequestXml = authnRequest.ToXml();
                HttpApplicationState application = System.Web.HttpContext.Current.ApplicationInstance.Application;
                if (Convert.ToBoolean(application[CertificateUtilities.SignedWithCertificate]) == true)
                {
                    X509Certificate2 certificate = (X509Certificate2)application[CertificateUtilities.CertificateKey];
                    if (certificate != null)
                    {
                        SAMLMessageSignature.Generate(authnRequestXml, certificate.PrivateKey, certificate);
                    }
                }

                return authnRequestXml;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAuthnRequest", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAuthnRequest");
            }
        }

        // RequestLoginAtIdentityProvider
        // Create the Authentication AuthnRequest message and send it to the Identity Provider
        private void RequestLoginAtIdentityProvider(string spToIdPBinding, string idProviderUrl, string ReturnUrl = null)
        {
            try
            {
                log.DebugFormat(">>SAMLLogOnUserControl.RequestLoginAtIdentityProvider {0}", spToIdPBinding);

                if (String.IsNullOrEmpty(spToIdPBinding))
                    throw new ArgumentNullException("spToIdPBinding");


                // Create the authentication request.
                XmlElement authnRequestXml = CreateAuthnRequest(spToIdPBinding);

                //-- This line of code for some reason keeps setting the return url to /WorxMgmt/default.aspx which doesnt
                //-- exist in worx mgmt, for now will hardcode in home page
                //string spResourceURL = utilities.CreateAbsoluteURL(FormsAuthentication.GetRedirectUrl("", false));

                // Create and cache the relay state so we remember which SP resource the user wishes 
                // to access after SSO. Set the Home Page where the  website will go after user authentication
                string spResourceURL = "";
                //If the return url is given, fall back to same page after login.
                // *** Need to be tested properly.
                if (String.IsNullOrEmpty(ReturnUrl))
                {
                    spResourceURL = config.HomePg;
                }
                else
                {
                    spResourceURL = ReturnUrl;
                }

                string relayState = RelayStateCache.Add(new RelayState(spResourceURL, null));

                // Send the authentication request to the identity provider over the selected binding.
                string idpURL = CreateSSOServiceURL(spToIdPBinding, idProviderUrl);

                switch (spToIdPBinding)
                {
                    case (SAMLIdentifiers.BindingURIs.HTTPRedirect):
                        {
                            ServiceProvider.SendAuthnRequestByHTTPRedirect(System.Web.HttpContext.Current.Response, idpURL, authnRequestXml, relayState, null);
                            break;
                        }

                    case (SAMLIdentifiers.BindingURIs.HTTPPost):
                        {
                            ServiceProvider.SendAuthnRequestByHTTPPost(System.Web.HttpContext.Current.Response, idpURL, authnRequestXml, relayState);

                            // Don't send this form.
                            System.Web.HttpContext.Current.Response.End();
                            break;
                        }

                    case (SAMLIdentifiers.BindingURIs.HTTPArtifact):
                        {
                            // Create the artifact.
                            string identificationURL = CreateAbsoluteURL("~/");
                            HTTPArtifactType4 httpArtifact = new HTTPArtifactType4(HTTPArtifactType4.CreateSourceId(identificationURL), HTTPArtifactType4.CreateMessageHandle());

                            //Cache the authentication request for subsequent sending using the artifact resolution protocol.
                            HTTPArtifactState httpArtifactState = new HTTPArtifactState(authnRequestXml, null);
                            HTTPArtifactStateCache.Add(httpArtifact, httpArtifactState);

                            //Send the artifact.
                            ServiceProvider.SendArtifactByHTTPArtifact(System.Web.HttpContext.Current.Response, idpURL, httpArtifact, relayState, false);

                            log.Debug("URL ==> " + idpURL);
                            break;
                        }

                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.RequestLoginAtIdentityProvider", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.RequestLoginAtIdentityProvider");
            }
        }

        // Create the SSO service URL.
        // Rather than have different endpoints for each binding we use the same endpoint and
        //identify the binding type by a query string parameter.
        private string CreateSSOServiceURL(string spToIdPBinding, string idPUrl)
        {
            try
            {
                log.DebugFormat(">>SAMLLogOnUserControl.CreateAbsoluteURL {0}", spToIdPBinding);
                string sourceUrl = new Uri(Request.Url, System.Web.VirtualPathUtility.ToAbsolute("~/")).ToString();
                //string SSOUrl = String.Format("{0}?{1}={2}&{3}={4}",                
                //                        config.IdpssoURL, bindingQueryParameter,                 
                //                        HttpUtility.UrlEncode(spToIdPBinding), "Source", HttpUtility.UrlEncode(sourceUrl));

                string SSOUrl = String.Format("{0}?{1}={2}&{3}={4}",
                                        idPUrl, bindingQueryParameter,
                                        HttpUtility.UrlEncode(spToIdPBinding), "Source", HttpUtility.UrlEncode(sourceUrl));

                log.InfoFormat("SSO URL = {0}", SSOUrl);
                return SSOUrl;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAbsoluteURL", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAbsoluteURL");
            }
        }

        #endregion

        #region ArtifactResponder_Control

        /// <summary>
        /// Artifact Responder 
        /// </summary>
        public void ArtifactResponder()
        {
            try
            {
                log.Debug(">>ArtifactResponder");
                ProcessArtifactResolve();
            }
            catch (Exception ex)
            {
                log.Error("ArtifactResponder", ex);
                throw;
            }
            finally
            {
                log.Debug("<<ArtifactResponder");
            }
        }

        private void ProcessArtifactResolve()
        {
            log.Debug(">>ProcessArtifactresolve");
            try
            {
                log.Info("SP: Processing artifact resolve request");

                // Receive the artifact resolve request.
                XmlElement artifactResolveXml = ArtifactResolver.ReceiveArtifactResolve(System.Web.HttpContext.Current.Request);

                ArtifactResolve artifactResolve = new ArtifactResolve(artifactResolveXml);

                // Get the artifact.
                HTTPArtifactType4 httpArtifact = new HTTPArtifactType4(artifactResolve.Artifact.ArtifactValue);

                // Remove the artifact state from the cache.
                HTTPArtifactState httpArtifactState = HTTPArtifactStateCache.Remove(httpArtifact);

                if (httpArtifactState != null)
                {
                    // Create an artifact response containing the cached SAML message.
                    ArtifactResponse artifactResponse = new ArtifactResponse();

                    artifactResponse.Issuer = new Issuer(CreateAbsoluteURL("~/"));
                    artifactResponse.SAMLMessage = httpArtifactState.SAMLMessage;
                    XmlElement artifactResponseXml = artifactResponse.ToXml();

                    // Send the artifact response.
                    ArtifactResolver.SendArtifactResponse(System.Web.HttpContext.Current.Response, artifactResponseXml);

                    log.Info("SP Processed artifact resolve request");
                }
            }

            catch (Exception ex)
            {
                log.Error(ex);
            }

            log.Debug("<<ProcessArtifactResolve");
        }

        #endregion

        #region SingleLogout_Control

        /// <summary>
        /// SAML logon request.
        /// </summary>
        public void SingleLogoutService()
        {
            string errorMessage;

            try
            {
                string userName = User.Identity.Name.ToString();
                log.Debug(">>SP Single Logout Service");

                // Create the configuration file
                config = (IdentityProviderSettings)System.Configuration.ConfigurationManager.GetSection(SectionNames.IDENTITY_PROVIDER_SECTION);

                // Determine whether a logout request or response message is being sent.
                // We use a query string parameter rather than having separate endpoints.
                string messageType = Request.QueryString[messageTypeParameter];

                // A logout request is sent by the IdP if logout is initiated by the IdP or another SP.
                // A logout response is sent by the IdP if logout is initiated by this SP.
                switch (messageType)
                {
                    case (MessageTypes.LogoutRequest):
                        {
                            log.Info("SP Received logout request");

                            // Receive the logout request.
                            LogoutRequest logoutRequest = null;

                            ReceiveLogoutRequest(ref logoutRequest);

                            // Logout locally.
                            if (logoutRequest != null)
                            {

                                FormsAuthentication.SignOut();
                                Session.Abandon();

                                //Create a logout response.
                                LogoutResponse logoutResponse = CreateLogoutResponse();

                                // Send the logout response.
                                SendLogoutResponse(logoutResponse);

                            }
                            break;
                        }

                    case (MessageTypes.LogoutResponse):
                        {
                            log.Info("SP Received logout response");

                            // Receive the logout response.
                            LogoutResponse logoutResponse = null;
                            string relayState = null;

                            ReceiveLogoutResponse(ref logoutResponse, relayState);
                            if (logoutResponse != null)
                            {
                                //Check whether the SAML response indicates success or an error and process accordingly.
                                if (logoutResponse.IsSuccess())
                                {
                                    FormsAuthentication.SignOut();
                                    Session.Abandon();
                                    // Redirect to the default page.
                                    Response.Redirect("~/", false);
                                }
                                else
                                {
                                    if (logoutResponse.Status.StatusMessage != null)
                                    {
                                        errorMessage = logoutResponse.Status.StatusMessage.Message;
                                        Response.Redirect("~/Error/CustomError?errorTitle=AuthenticationFailure&errorMsg=" + errorMessage);
                                    }
                                }
                            }
                            break;
                        }

                    default:
                        {
                            log.Info("SP Invalid message type.");
                            break;
                        }
                }
            }

            catch (Exception ex)
            {
                log.Error("SP Error in single logout service.", ex);
            }
        }

        //Create an absolute URL from an application relative URL.
        private string CreateAbsoluteURL(string relativeURL)
        {
            return new Uri(Request.Url, System.Web.VirtualPathUtility.ToAbsolute(relativeURL)).ToString();
        }

        // Receive the logout request.
        private void ReceiveLogoutRequest(ref LogoutRequest logoutRequest)
        {
            log.Debug(">>SP Receiving logout request.");
            try
            {

                string relayState = null;
                bool isSigned = false;

                XmlElement logoutRequestXml = null;

                //Receive the logout request over SOAP.
                ComponentSpace.SAML2.Profiles.SingleLogout.SingleLogoutService.ReceiveLogoutRequestByHTTPRedirect(System.Web.HttpContext.Current.Request, out logoutRequestXml, out relayState, out isSigned, null);
                // Deserialize the XML.
                logoutRequest = new LogoutRequest(logoutRequestXml);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }

            log.Debug("<<SP Received logout request.");
        }

        // Create a logout response.
        private LogoutResponse CreateLogoutResponse()
        {
            log.Debug(">>SP Creating logout response.");
            LogoutResponse logoutResponse = new LogoutResponse();
            try
            {
                logoutResponse.Issuer = new Issuer(CreateAbsoluteURL("~/"));
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }

            log.Debug("<<SP Created logout response.");
            return (logoutResponse);
        }

        // Send the logout response.
        private void SendLogoutResponse(LogoutResponse logoutResponse)
        {
            log.Debug(">>SP Sending logout response.");

            try
            {
                // Serialize the logout response for transmission.
                XmlElement logoutResponseXml = logoutResponse.ToXml();

                // Send the logout response over SOAP.
                //ComponentSpace.SAML2.Profiles.SingleLogout.SingleLogoutService.SendLogoutResponseBySOAP(Response, logoutResponseXml);
                ComponentSpace.SAML2.Profiles.SingleLogout.SingleLogoutService.SendLogoutResponseByHTTPRedirect(System.Web.HttpContext.Current.Response, config.IdpLogoutURL, logoutResponseXml, null, null);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }

            log.Debug("<<SP Sent logout response.");
        }

        // Receive the logout response.
        private void ReceiveLogoutResponse(ref LogoutResponse logoutResponse, string relayState)
        {
            log.Debug(">>SP Receiving logout response.");
            try
            {
                // Receive the logout response over HTTP redirect.
                XmlElement logoutResponseXml = null;
                bool signed = false;
                ComponentSpace.SAML2.Profiles.SingleLogout.SingleLogoutService.ReceiveLogoutResponseByHTTPRedirect(System.Web.HttpContext.Current.Request, out logoutResponseXml, out relayState, out signed, null);

                // Deserialize the XML.
                logoutResponse = new LogoutResponse(logoutResponseXml);

            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }

            log.Debug("<<SP Received logout response");
        }

        #endregion

        #region SAML_LogOff_Control

        /// <summary>
        /// SAML logon Off request.
        /// </summary>
        public void SAMLLogOff()
        {
            try
            {
                log.Debug(">>SAMLLogOffUserControl.Page_Load");

                config = (IdentityProviderSettings)System.Configuration.ConfigurationManager.GetSection(SectionNames.IDENTITY_PROVIDER_SECTION);
                if (config == null)
                {
                    throw new Exception("Unable to load IdentityProvider settings from web.config");
                }

                // Send the logout request to the identity provider
                sendLogoutRequest();
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOffUserControl.Page_Load", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOffUserControl.Page_Load");
            }
        }

        private string CreateURLFromRelativeUrl(Uri uriBase, string relativeURL)
        {
            log.Debug(">>Logout--CreateURLFromRelativeURL " + "Url :- " + uriBase.AbsoluteUri);
            Uri newUrl = null;

            try
            {
                // Get the URI parts
                string[] URLparts = uriBase.Segments;
                log.InfoFormat("The Number of Segments is :- {0}", URLparts.Count().ToString());

                if (URLparts.Count() > 2)
                {
                    string urlBase = uriBase.Scheme + "://" + uriBase.Host + URLparts[0] + URLparts[1] + relativeURL;
                    newUrl = new Uri(urlBase);
                }
            }

            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }
            finally
            {
                log.Debug("<<Logout--CreateURLFromRelativeURL");
            }


            log.InfoFormat("Result URL is  :- {0}", newUrl.ToString());
            return newUrl.ToString();
        }


        /// <summary>
        /// This method gets the url that the identityprovider
        /// will use to return to after logout
        /// </summary>
        /// <returns></returns>
        private string getResponseUrl()
        {
            log.Debug(">>getResponseUrl");
            try
            {
                string returnUrl = config.HomePg;

                if (returnUrl.Last() != '/')
                {
                    returnUrl = returnUrl + '/';
                }

                return returnUrl;
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }
            finally
            {
                log.Debug("<<getResponseUrl");
            }
        }

        /// <summary>
        /// Sends a logout request to the identity provider
        /// </summary>
        private void sendLogoutRequest()
        {
            try
            {
                log.Debug(">>Logout--SendLogoutRequest");

                // Create a logout request.
                LogoutRequest logoutRequest = new LogoutRequest();

                // Get the URL of this web Application so that it can be used by the 
                // Identity Provider to return to.
                string issuerURLBase = getResponseUrl();

                // Add this information to the logout request
                if (issuerURLBase != null)
                {
                    logoutRequest.Issuer = new Issuer(issuerURLBase);
                    log.Info(" logoutResuestIssuer : " + logoutRequest.Issuer.NameIdentifier);
                }

                // Set the NameId to the currently logged in User
                logoutRequest.NameID = new NameID(System.Web.HttpContext.Current.User.Identity.Name);

                // Create and cache the relay state so we remember which SP resource the user wishes 
                // to access after SSO. Set the Home Page where the  website will go after user authentication
                string spResourceURL = CreateURLFromRelativeUrl(System.Web.HttpContext.Current.Request.Url, config.RelativeHomePg);
                string relayState = RelayStateCache.Add(new RelayState(spResourceURL, null));

                // Serialize the logout request to XML for transmission.
                XmlElement logoutRequestXml = logoutRequest.ToXml();

                // Send the logout request to the IdP over HTTP redirect.
                String logoutURL = config.IdpLogoutURL;

                log.Info("LogoutUrl : " + logoutURL);
                ComponentSpace.SAML2.Profiles.SingleLogout.SingleLogoutService.SendLogoutRequestByHTTPRedirect(System.Web.HttpContext.Current.Response, logoutURL, logoutRequestXml, relayState, null);
            }
            // Catch and log any exceptions
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }
            finally
            {
                log.Debug("<<Logout--SendLogoutRequest");
            }
        }

        #endregion

        #region AssertionConsumerService_Control


        /// <summary>
        /// Assertion consumer service urls.
        /// </summary>
        public void AssertionConsumerService()
        {
            try
            {
                log.Debug(">>AssertionConsumerService.Page_Load");

                // Create the configuration file
                config = (IdentityProviderSettings)System.Configuration.ConfigurationManager.GetSection(SectionNames.IDENTITY_PROVIDER_SECTION);
                if (config == null)
                {
                    throw new Exception("Unable to read Identity Provider settings from the web.config");
                }

                ProcessSAMLResponse();
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
            finally
            {
                log.Debug("<<AssertionConsumerService.Page_Load");
            }
        }

        // Process the SAML response returned by the identity provider in response
        // to the authentication request sent by the service provider.
        private void ProcessSAMLResponse()
        {
            try
            {
                log.Debug(">>AssertionConsumerService.ProcessSAMLResponse");

                //Receive the SAML response.
                SAMLResponse samlResponse = null;
                string relayState = null;

                ReceiveSAMLResponse(ref samlResponse, ref relayState);
                if (samlResponse != null)
                {
                    //Check whether the SAML response indicates success or an error and process accordingly.
                    if (samlResponse.IsSuccess())
                    {
                        ProcessSuccessSAMLResponse(samlResponse, relayState);
                    }
                    else
                    {
                        if (samlResponse.Status.StatusMessage.ToString() == "AuthenticationViaADFS")
                            ProcessADFSResponse(samlResponse, relayState);
                        else
                            ProcessErrorSAMLResponse(samlResponse);
                    }
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }
            finally
            {
                log.Debug("<<AssertionConsumerService.ProcessSAMLResponse");
            }
        }

        // Process a successful SAML response.
        private void ProcessSuccessSAMLResponse(SAMLResponse samlResponse, string relayState)
        {
            try
            {
                log.Debug(">>AssertionConsumerService.ProcessSuccessSAMLResponse");

                if (samlResponse == null)
                    throw new ArgumentNullException("samlResponse");

                SAMLAssertion samlAssertion = null;
                // if we are using encrypted assertions then 

                IList<EncryptedAssertion> encryptedAssertions = samlResponse.GetEncryptedAssertions();
                if ((encryptedAssertions != null) && (encryptedAssertions.Count > 0))
                {
                    X509Certificate2 certificate = LoadIdentityProviderCertificate();

                    samlAssertion = encryptedAssertions[0].Decrypt(certificate, null);
                }
                else
                {
                    // Extract the asserted identity from the SAML response.
                    samlAssertion = (SAMLAssertion)samlResponse.Assertions[0];
                }

                // Get the subject name identifier.
                string userName = samlAssertion.Subject.NameID.NameIdentifier;

                // Get the originally requested resource URL from the relay state.
                RelayState cachedRelayState = RelayStateCache.Remove(relayState);

                if (cachedRelayState == null)
                    log.Info("SP Nothing in cache");
                else
                {
                    // Create a login context for the asserted identity.
                    FormsAuthentication.SetAuthCookie(userName, false);

                    // Get the users party type
                    SessionManager.Current.PartyType = (PartyTypes)Enum.Parse(typeof(PartyTypes), samlAssertion.GetAttributeValue("PartyType"), true);

                    // Get the role from the SAML message
                    string role = samlAssertion.GetAttributeValue("UserTy");
                    Session["LoggedInRole"] = role;
                    Session["AuthMechanism"] = "InverCloud";

                    // Get the Tenant Name from the SAML message
                    Session["TenantName"] = samlAssertion.GetAttributeValue("TenantName");

                    // Store the parameters in the session
                    SessionManager.Current.TenantId = new Guid(samlAssertion.GetAttributeValue("TenantId"));
                    SessionManager.Current.LoggedInRole = role;

                    // Get the Tenant Store id and store it in session
                    SessionManager.Current.TenantIdStore = samlAssertion.GetAttributeValue("TenantStoreId");
                    SessionManager.Current.TenantName = samlAssertion.GetAttributeValue("TenantName");
                    SessionManager.Current.TenantConnInfo = new AspiraCloud.ServiceProxy.Common.ConnectionInfo();
                    SessionManager.Current.TenantConnInfo.InverCloudConnString = samlAssertion.GetAttributeValue("InverCloudConnString");
                    SessionManager.Current.TenantConnInfo.TenantId = new Guid(samlAssertion.GetAttributeValue("TenantId"));
                    SessionManager.Current.TenantConnInfo.TenantStoreId = new Guid(samlAssertion.GetAttributeValue("TenantStoreId"));
                    SessionManager.Current.TenantConnInfo.AuditConnString = samlAssertion.GetAttributeValue("AuditConnString");
                    SessionManager.Current.TenantConnInfo.AppConnString = samlAssertion.GetAttributeValue("AppConnString");
                    SessionManager.Current.UserId = long.Parse(samlAssertion.GetAttributeValue("UserId"));

                    // Set the User Tenancy Id attribute
                    SessionManager.Current.UserTenantId = samlAssertion.GetAttributeValue("UserTenantId");

                    // Set the User Tenancy Name attribute 
                    SessionManager.Current.UserTenantName = samlAssertion.GetAttributeValue("UserTenantName");

                    // Set the Application Name and Application Id
                    SessionManager.Current.ApplicationName = samlAssertion.GetAttributeValue("ApplicationName");
                    SessionManager.Current.ApplicationId = samlAssertion.GetAttributeValue("ApplicationId");

                    // Set the BrandingTenantName
                    SessionManager.Current.BrandingTenantName = samlAssertion.GetAttributeValue("BrandingTenantName");
                    SessionManager.Current.BrandingTenantId = new Guid(samlAssertion.GetAttributeValue("BrandingTenantId"));

                    //Redirect to the originally requested resource URL.
                    Response.Redirect(cachedRelayState.ResourceURL, false);

                    log.Info("SP Processed successful SAML response");
                }
            }
            catch (Exception ex)
            {
                log.Error("AssertionConsumerService.ProcessSuccessSAMLResponse", ex);
                throw;
            }
            finally
            {
                log.Debug("<<AssertionConsumerService.ProcessSuccessSAMLResponse");
            }
        }

        /// <summary>
        /// Load the identity provider certificate. This is used to decrypt any encrypted saml assertions
        /// </summary>
        /// <returns>certificate to be</returns>
        private X509Certificate2 LoadIdentityProviderCertificate()
        {
            try
            {
                log.Debug(">>AssertionConsumerService.LoadIdentityProviderCertificate");

                IdentityProviderSettings config = (IdentityProviderSettings)ConfigurationManager.GetSection(SectionNames.IDENTITY_PROVIDER_SECTION);
                if (config == null)
                {
                    throw new Exception(
                        String.Format("Unable to retreive '{0}' section from web.config",
                            SectionNames.IDENTITY_PROVIDER_SECTION));
                }

                return CertificateUtilities.LoadCertificate(config.CertificateName, config.CertificatePassword);
            }
            catch (Exception ex)
            {
                log.Error("AssertionConsumerService.LoadIdentityProviderCertificate", ex);
                throw;
            }
            finally
            {
                log.Debug("<<AssertionConsumerService.LoadIdentityProviderCertificate");
            }
        }

        // Process an error SAML response.
        private void ProcessErrorSAMLResponse(SAMLResponse samlResponse)
        {
            try
            {
                log.Debug(">>ProcessErrorSAMLResponse");

                string errorMessage = null;

                if (samlResponse.Status.StatusMessage != null)
                    errorMessage = samlResponse.Status.StatusMessage.Message;

                string redirectURL = String.Format(config.SpErrorLoginURL + "?{0}={1}", errorQueryParameter, HttpUtility.UrlEncode(errorMessage));

                // Show the error 
                //AspiraCloud.WebSite.TenantManagement.Controllers.ErrorController errorPg = new  AspiraCloud.WebSite.TenantManagement.Controllers.ErrorController();
                //errorPg.CustomError("Authentication Failure", errorMessage);

                //Response.Redirect("/error/Error/", false);
                Response.Redirect("~/Error/CustomError?errorTitle=AuthenticationFailure&errorMsg=" + errorMessage);

            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }
            finally
            {
                log.Debug("<<ProcessErrorSAMLResponse");
            }
        }


        // Receive the SAML response from the identity provider.
        private void ReceiveSAMLResponse(ref SAMLResponse samlResponse, ref string relayState)
        {
            try
            {
                log.Debug(">>AssetionConsumerService.ReceiveSAMLResponse");
                XmlElement samlResponseXml = null;

                // Determine the binding used for the response
                string bindingType = Request.QueryString["binding"];
                if (bindingType == null)
                    bindingType = SAMLIdentifiers.BindingURIs.HTTPPost;

                switch (bindingType)
                {

                    case SAMLIdentifiers.BindingURIs.HTTPPost:
                        ServiceProvider.ReceiveSAMLResponseByHTTPPost(System.Web.HttpContext.Current.Request, out samlResponseXml, out relayState);
                        break;


                    case SAMLIdentifiers.BindingURIs.HTTPArtifact:

                        // Receive the SAML response over the specified binding.
                        //XmlElement samlResponseXml = null;

                        // Receive the artifact.
                        HTTPArtifact httpArtifact = null;
                        ComponentSpace.SAML2.Profiles.SSOBrowser.ServiceProvider.ReceiveArtifactByHTTPArtifact(System.Web.HttpContext.Current.Request, false, out httpArtifact, out relayState);

                        // Create an artifact resolve request.
                        ArtifactResolve artifactResolve = new ArtifactResolve();
                        artifactResolve.Issuer = new Issuer(CreateAbsoluteURL("~/"));
                        artifactResolve.Artifact = new Artifact(httpArtifact.ToString());
                        XmlElement artifactResolveXml = artifactResolve.ToXml();

                        // Send the artifact resolve request and receive the artifact response.
                        string spArtifactResponderURL = config.IdpArtifactResponderURL;

                        if (String.IsNullOrEmpty(spArtifactResponderURL) == true)
                        {
                            throw new Exception("Unable to retreive Artifact Responder URL from the web.config");
                        }

                        XmlElement artifactResponseXml = ArtifactResolver.SendRequestReceiveResponse(spArtifactResponderURL, artifactResolveXml);

                        ArtifactResponse artifactResponse = new ArtifactResponse(artifactResponseXml);

                        // Extract the SAML response from the artifact response.
                        samlResponseXml = artifactResponse.SAMLMessage;
                        if (samlResponseXml == null)
                        {
                            throw new Exception("No SAML Message contained within artifact response.");
                        }

                        // if we have configued the 509 certificate in the identity provider web.config
                        // section then we expect that the saml response should be signed with it, failint it
                        // otherwise.
                        HttpApplicationState application = System.Web.HttpContext.Current.ApplicationInstance.Application;

                        if (Convert.ToBoolean(application[CertificateUtilities.SignedWithCertificate]) == true)
                        {
                            X509Certificate2 certificate = (X509Certificate2)application[CertificateUtilities.CertificateKey];
                            if (certificate == null)
                                throw new Exception("Unable to obtain certificate to verify SAML response");



                            if (!SAMLMessageSignature.Verify(samlResponseXml, certificate))
                                throw new Exception("SAML Response failed to verify against configured certificate");
                        }

                        // Deserialize the XML.
                        samlResponse = new SAMLResponse(samlResponseXml);
                        break;

                    default:
                        throw new Exception("Invalid identity provider to service provider binding");
                }
            }

            catch (Exception ex)
            {
                log.Error("AssetionConsumerService.ReceivedSAMLResponse", ex);
                throw;
            }
            finally
            {
                log.Debug("<<AssertionConsumerService.ReceiveSAMLResponse");
            }
        }

        // Process a SAML response from a tenant having ADFS authentication
        private void ProcessADFSResponse(SAMLResponse samlResponse, string relayState)
        {
            log.Debug(">>SP ProcessADFSResponse");

            try
            {
                // Extract the asserted identity from the SAML response.
                SAMLAssertion samlAssertion = (SAMLAssertion)samlResponse.Assertions[0];

                // Get the subject name identifier.
                string userName = samlAssertion.Subject.NameID.NameIdentifier;

                // Get the Tenant Name from the SAML message
                Session["TenantName"] = samlAssertion.GetAttributeValue("TenantName");

                // Set up the Session Id for the TenantId
                SessionManager.Current.TenantConnInfo = new AspiraCloud.ServiceProxy.Common.ConnectionInfo();

                // Set the ADFSServer attribute
                AttributeStatement attributeStatementADFSServer = new AttributeStatement();
                attributeStatementADFSServer.Attributes.Add(new SAMLAttribute("ADFSServer", SAMLIdentifiers.AttributeNameFormats.Basic, null, SessionManager.Current.DataForAuthMechanism));
                samlAssertion.Statements.Add(attributeStatementADFSServer);

                // Get the url of the ADFS Identity Provider
                string ADFSUrl = samlAssertion.GetAttributeValue("ADFSServer");

                // Get the URL of the current website
                string issuerUrl = CreateAbsoluteURL("~/");
                // Replace http with https
                if (issuerUrl.StartsWith("http:", StringComparison.InvariantCultureIgnoreCase) == true)
                    issuerUrl = "https:" + issuerUrl.Substring(5);

                // Get the URL of the page that the Identity provider will return to.
                string absUrlToReturnTo = CreateAbsoluteURL("~/SAML/AdfsAssertionConsumerService.aspx?tname=tenyx");
                if (absUrlToReturnTo.StartsWith("http:", StringComparison.InvariantCultureIgnoreCase) == true)
                    absUrlToReturnTo = "https:" + absUrlToReturnTo.Substring(5);

                // In order to login at the ADFS Identity provider then generate the request from this page.
                RequestLoginAtADFSIdentityProvider(SAMLIdentifiers.BindingURIs.HTTPPost, ADFSUrl, issuerUrl, absUrlToReturnTo, relayState);
                System.Web.HttpContext.Current.Response.End();
            }
            catch (Exception ex)
            {
                log.Error(ex);
                throw;
            }

            log.Debug("<<SP ProcessSuccessSAMLResponse");
        }

        // RequestLoginAtIdentityProvider
        // Create the Authentication AuthnRequest message and send it to the Identity Provider
        private void RequestLoginAtADFSIdentityProvider(string spToIdPBinding, string idProviderUrl, string issuerUrl, string absoluteUrl, string relayState)
        {
            try
            {

                log.DebugFormat(">>AssertionConsumerService.RequestLoginAtIdentityProvider {0}", spToIdPBinding);

                // Check the binding parameter is specified
                if (String.IsNullOrEmpty(spToIdPBinding) == true)
                {
                    throw new ArgumentNullException("spToIdPBinding");
                }

                // Create the authentication request.
                XmlElement authnRequestXml = CreateAuthnRequest(spToIdPBinding, issuerUrl, absoluteUrl, idProviderUrl);

                // Create and cache the relay state so we remember which SP resource the user wishes 
                // to access after SSO. Set the Home Page where the  website will go after user authentication
                string spResourceURL = absoluteUrl;

                // For ADFS 2.0 the RelayState is configured in a specified format. The following method is 
                // called to generate the format of RelayState for ADFS
                string ADFSRelayState = GenerateRelayStateForADFS(relayState);

                // Create a cookie to store the RelayState as currently the ADFS Server does not return 
                // the relaystate to the Service Provider.Check if the cookie is already there.
                RemoveCookie("RelayStateBeforeFedAuth", System.Web.HttpContext.Current.Response, System.Web.HttpContext.Current.Request);

                // Create cookie object 
                HttpCookie cookie = new HttpCookie("RelayStateBeforeFedAuth");
                // Set the cookies value 
                cookie.Value = relayState;
                //Set the cookie to expire in 10 minutes
                DateTime dtNow = DateTime.Now;
                TimeSpan tsMinute = new TimeSpan(00, 0, 10, 0);
                cookie.Expires = dtNow + tsMinute;
                // Add the cookie 
                Response.Cookies.Add(cookie);

                string relayStateX = Request.Cookies["RelayStateBeforeFedAuth"].Value;

                // Send the authentication request to the identity provider over the selected binding.
                string idpURL = CreateADFSEndPointURL(idProviderUrl);

                switch (spToIdPBinding)
                {
                    case (SAMLIdentifiers.BindingURIs.HTTPRedirect):
                        {
                            ServiceProvider.SendAuthnRequestByHTTPRedirect(System.Web.HttpContext.Current.Response, idpURL, authnRequestXml, ADFSRelayState, null);
                            break;
                        }

                    case (SAMLIdentifiers.BindingURIs.HTTPPost):
                        {
                            ServiceProvider.SendAuthnRequestByHTTPPost(System.Web.HttpContext.Current.Response, idpURL, authnRequestXml, ADFSRelayState);

                            // Don't send this form.
                            //HttpContext.Current.Response.End();
                            break;
                        }

                    case (SAMLIdentifiers.BindingURIs.HTTPArtifact):
                        {
                            // Create the artifact.
                            //string identificationURL = CreateAbsoluteURL("~/","");
                            string identificationURL = absoluteUrl;

                            HTTPArtifactType4 httpArtifact = new HTTPArtifactType4(HTTPArtifactType4.CreateSourceId(identificationURL), HTTPArtifactType4.CreateMessageHandle());

                            //Cache the authentication request for subsequent sending using the artifact resolution protocol.
                            HTTPArtifactState httpArtifactState = new HTTPArtifactState(authnRequestXml, null);
                            HTTPArtifactStateCache.Add(httpArtifact, httpArtifactState);

                            //Send the artifact.
                            ServiceProvider.SendArtifactByHTTPArtifact(System.Web.HttpContext.Current.Response, idpURL, httpArtifact, ADFSRelayState, false);
                            break;
                        }

                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.RequestLoginAtIdentityProvider", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.RequestLoginAtIdentityProvider");
            }
        }

        /// <summary>
        /// Create the ADFS endpoint. Note this must end in / for the adfs page load 
        /// to work correctly. The web site had extensions configured to treat the 
        /// trailing / as a page. 
        /// </summary>
        /// <returns></returns>
        private string CreateADFSEndPointURL(string idProviderUrl)
        {
            if (String.IsNullOrEmpty(idProviderUrl) == true)
            {
                throw new Exception("ADFSEndPointURL is not configured.");
            }

            if (idProviderUrl.EndsWith("/") == false)
            {
                idProviderUrl = idProviderUrl + "/";
            }

            return idProviderUrl;
        }

        // Create the SSO service URL.
        // Rather than have different endpoints for each binding we use the same endpoint and
        //identify the binding type by a query string parameter.
        private string CreateSSOServiceURL(string spToIdPBinding, string idPUrl, string sourceUrl)
        {
            try
            {

                log.DebugFormat(">>SAMLLogOnUserControl.CreateAbsoluteURL {0}", spToIdPBinding);

                //string sourceUrl = new Uri(Request.Url, ResolveUrl("~/")).ToString();
                //string SSOUrl = String.Format("{0}?{1}={2}&{3}={4}",                
                //                        config.IdpssoURL, bindingQueryParameter,                 
                //                        HttpUtility.UrlEncode(spToIdPBinding), "Source", HttpUtility.UrlEncode(sourceUrl));

                string SSOUrl = String.Format("{0}?{1}={2}&{3}={4}",
                                        idPUrl, bindingQueryParameter,
                                        HttpUtility.UrlEncode(spToIdPBinding), "Source", HttpUtility.UrlEncode(sourceUrl));

                log.InfoFormat("SSO URL = {0}", SSOUrl);

                return SSOUrl;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAbsoluteURL", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAbsoluteURL");
            }
        }

        // Create the assertion consumer service URL.
        // Rather than have different endpoints for each binding we use the same endpoint and
        // identify the binding type by a query string parameter.
        private string CreateAssertionConsumerServiceURL(string baseUrl, string absoluteUrl)
        {

            try
            {
                log.Debug(">>SAMLLogOnUserControl.CreateAssertionConsumerServiceURL");

                if (config == null)
                {
                    throw new Exception("config is not initialised");
                }

                if (String.IsNullOrEmpty(config.SpAssertionURL) == true)
                {
                    throw new Exception("SP Assertion URL not configured correctly");
                }

                //string assertionURL = string.Format("{0}?{1}={2}",
                //              CreateAbsoluteURL(config.SpAssertionURL,baseUrl),
                //              bindingQueryParameter,
                //              HttpUtility.UrlEncode(SAMLIdentifiers.BindingURIs.HTTPArtifact));

                string assertionURL = string.Format("{0}?{1}={2}",
                              absoluteUrl, bindingQueryParameter,
                              HttpUtility.UrlEncode(SAMLIdentifiers.BindingURIs.HTTPArtifact));

                log.InfoFormat("assertion consumer url {0}", assertionURL);
                return assertionURL;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAssertionConsumerServiceURL", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAssertionConsumerServiceURL");
            }
        }

        // Create an authentication request.
        private XmlElement CreateAuthnRequest(string spToIdPBinding, string issuerURL, string absoluteUrl, string idProviderUrl)
        {
            try
            {
                log.DebugFormat(">>SAMLLogOnUserControl.CreateAuthnRequest {0}", spToIdPBinding);

                // Create some URLs to identify the service provider to the identity provider.
                // As we're using the same endpoint for the different bindings, add a query string 
                // parameter to identify the binding.
                //string issuerURL = CreateAbsoluteURL("~/");
                XmlElement authnRequestXml;

                //string assertionConsumerServiceURL = CreateAssertionConsumerServiceURL(baseUrl,absoluteUrl);

                // Create the authentication request.
                AuthnRequest authnRequest = new AuthnRequest();
                authnRequest.Destination = idProviderUrl;
                authnRequest.Issuer = new Issuer(issuerURL);
                authnRequest.ForceAuthn = false;
                authnRequest.NameIDPolicy = new NameIDPolicy(null, null, true);
                authnRequest.ProtocolBinding = SAMLIdentifiers.BindingURIs.HTTPPost;
                authnRequest.AssertionConsumerServiceURL = absoluteUrl;
                //authnRequest.Extensions.Data= 
                //Serialize the authentication request to XML for transmission.
                authnRequestXml = authnRequest.ToXml();
                return authnRequestXml;
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.CreateAuthnRequest", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.CreateAuthnRequest");
            }
        }

        // Generate the ADFS Relay parameter.
        // The relay string contains a string to access the Destination URL stored in the cache. 
        // Authentication.
        private string GenerateRelayStateForADFS(string relay)
        {
            try
            {
                log.Debug(">>SAMLLogOnUserControl.GenerateRelayStateForADFS");
                StringBuilder adfsRelayString = new StringBuilder();

                // Add RPID parameter to indicater the 
                adfsRelayString.Append("RPID=");
                adfsRelayString.Append(HttpUtility.UrlEncode("https://JOHNMAGUIRE-PC/TenantManagementWebsite/SAML/AdfsAssertionConsumerService.aspx"));

                // Add the relay string to indicate the ultimate destination address
                adfsRelayString.Append("&");
                adfsRelayString.Append(HttpUtility.UrlEncode("RelayState=RPID="));

                //Add the relay to the ultimate destination
                adfsRelayString.Append(HttpUtility.UrlEncode(relay));
                return adfsRelayString.ToString();
            }
            catch (Exception ex)
            {
                log.Error("SAMLLogOnUserControl.GenerateRelayStateForADFS", ex);
                throw;
            }
            finally
            {
                log.Debug("<<SAMLLogOnUserControl.GenerateRelayStateForADFS");
            }
        }

        // Function used to remove the cookie used to store the RelayState
        private void RemoveCookie(string key, HttpResponse response, HttpRequest request)
        {
            if (request == null) return;
            if (response == null) return;
            if (string.IsNullOrEmpty(key))
                return;

            if (response.Cookies[key] != null)
            {
                response.Cookies.Remove(key);
                request.Cookies.Remove(key);
            }
        }

        #endregion
    }
}