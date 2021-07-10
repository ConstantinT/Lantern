using Lantern.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;

namespace Lantern
{
    class Tokenator
    {

        private static string RequestForPendingAuthentication(string code, string clientID,  string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("code",code),
                new KeyValuePair<string, string>("grant_type","urn:ietf:params:oauth:grant-type:device_code"),
                new KeyValuePair<string, string>("client_id", clientID)
                });

            return Helper.postToTokenEndpoint(formContent, proxy);

        }

        private static string RequestDeviceCode(string clientid, string resourceid, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("client_id", clientid),
                new KeyValuePair<string, string>("resource", resourceid)
                });
            return Helper.postToDeviceCodeEndpoint(formContent, proxy);
        }

        private static string RequestP2PCertificate(string JWT, string tenant, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("request", JWT)
                });

            return Helper.postToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string AuthenticateWithClientIDandSecret(string clientID, string clientSecret, string tenant, string proxy, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>(ressourceId, ressourceId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
            return Helper.postToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string AuthenticateWithUserNameAndPassword(string username, string password, string tenant, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password)
                });
            return Helper.postToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string AuthenticateWithRefreshTokenToTenant(string refreshToken, string tenant, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
            return Helper.postToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string AuthenticateWithRefreshToken(string refreshToken, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
            return Helper.postToTokenEndpoint(formContent, proxy);
        }
        private static string AuthenticateWithCode(string code, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
                new KeyValuePair<string, string>("code", code)
                });

            return Helper.postToTokenEndpoint(formContent, proxy);
        }

        public static string GetP2PCertificate(string JWT, string tenant, string proxy)
        {
            string result;
            result = RequestP2PCertificate(JWT, tenant, proxy);
            return result;
        }

        public static string GetTokenFromPRTAndDerivedKey(string PRT, string DerivedKey, string Context, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            string prtCookie = Helper.createPRTCookie(PRT, Context, DerivedKey, Proxy);
            string code = Helper.getCodeFromPRTCookie(prtCookie, Proxy, resourceID, clientID);
            result = AuthenticateWithCode(code, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromPRTAndSessionKey(string PRT, string SessionKey, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            var context = Helper.GetByteArray(24);
            var decodedKey = Helper.Base64Decode(SessionKey);
            var derivedKey = Helper.createDerivedKey(decodedKey, context);

            var contextHex = Helper.Binary2Hex(context);
            var derivedSessionKeyHex = Helper.Binary2Hex(derivedKey);

            string prtCookie = Helper.createPRTCookie(PRT, contextHex, derivedSessionKeyHex, Proxy);
            string code = Helper.getCodeFromPRTCookie(prtCookie, Proxy, resourceID, clientID);
            result = AuthenticateWithCode(code, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromPRTCookie(string PRTCookie, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            string code = Helper.getCodeFromPRTCookie(PRTCookie, Proxy, resourceID, clientID);
            result = AuthenticateWithCode(code, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromRefreshToken(string RefreshToken, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = AuthenticateWithRefreshToken(RefreshToken, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromRefreshTokenToTenant(string RefreshToken, string Tenant, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = AuthenticateWithRefreshTokenToTenant(RefreshToken, Tenant, Proxy, clientID, resourceID);
            return result;
        }


        public static string GetTokenFromUsernameAndPassword(string Username, string Password, string Tenant, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = AuthenticateWithUserNameAndPassword(Username, Password, Tenant, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenWithClientIDAndSecret(string ClientID, string ClientSecret, string Tenant, string Proxy, string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = AuthenticateWithClientIDandSecret(ClientID, ClientSecret, Tenant, Proxy, resourceID);
            return result;
        }

        public static string GetTokenFromDeviceCode(string ClientID, string ResourceID, string Proxy)
        {
            string result = null;
            result = RequestDeviceCode(ClientID, ResourceID, Proxy);
            var InitDeviceCode = JsonConvert.DeserializeObject<DeviceCodeResp>(result);
            Console.WriteLine(JToken.FromObject(InitDeviceCode).ToString(Formatting.Indented));

            var SecondsToWait = InitDeviceCode.interval;
            int WaitedTime = 0;
            while (WaitedTime < InitDeviceCode.expires_in)
            {
                result = RequestForPendingAuthentication(InitDeviceCode.device_code, ClientID, Proxy);
                JToken parsedesults = JToken.Parse(result);
                if (parsedesults["error"] != null)
                {
                    Console.WriteLine("[+] Response from Azure: " + parsedesults["error"]);
                }else
                {
                    return result;
                }
                System.Threading.Thread.Sleep(SecondsToWait * 1000);
                WaitedTime += SecondsToWait;
                result = null;
            }
            return null;
        }

        public static string getToken(TokenOptions opts, string clientID = null, string resourceID = null)
        {
            string result = null;

            if (clientID == null && resourceID == null)
            {
                clientID = opts.ClientID;
                resourceID = opts.ResourceID;
            }

            if (opts.Devicecode)
            {
                result = GetTokenFromDeviceCode(clientID, resourceID, opts.Proxy);
            }
            else if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = GetTokenFromPRTAndDerivedKey(opts.PRT, opts.DerivedKey, opts.Context, opts.Proxy, clientID, resourceID);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                result = GetTokenFromPRTAndSessionKey(opts.PRT, opts.SessionKey, opts.Proxy, clientID, resourceID);
            }
            else if (opts.PrtCookie != null)
            {
                result = GetTokenFromPRTCookie(opts.PrtCookie, opts.Proxy, clientID, resourceID);
            }
            else if (opts.RefreshToken != null)
            {
                result = GetTokenFromRefreshTokenToTenant(opts.RefreshToken, opts.Tenant, opts.Proxy, clientID, resourceID);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                result = GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Tenant, opts.Proxy, clientID, resourceID);
            }
            else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
            {
                result = GetTokenWithClientIDAndSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy, opts.ResourceID);
            }
            else
            {
                Console.WriteLine("[-] Please set the corect arguments.");
                return null;
            }
            return result;
        }


    }
}
