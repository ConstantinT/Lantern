using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;

namespace Lantern
{
    class Tokenator
    {
        

        private static string requestP2PCertificate(string JWT, string tenant, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("request", JWT)
                });

            return Helper.postToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string authenticateWithClientIDandSecret(string clientID, string clientSecret, string tenant, string proxy, string ressourceId)
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

        private static string authenticateWithUserNameAndPassword(string username, string password, string proxy, string clientID, string ressourceId)
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
            return Helper.postToTokenEndpoint(formContent, proxy);
        }

        private static string authenticateWithRefreshTokenToTenant(string refreshToken, string tenant, string proxy, string clientID, string ressourceId)
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

        private static string authenticateWithRefreshToken(string token, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("refresh_token", token),
                });
            return Helper.postToTokenEndpoint(formContent, proxy);
        }
        private static string authenticateWithCode(string code, string proxy, string clientID, string ressourceId)
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

        public static string getP2PCertificate(string JWT, string tenant, string proxy)
        {
            string result;
            result = requestP2PCertificate(JWT, tenant, proxy);
            return result;
        }

        public static string getTokenFromPRTAndDerivedKey(string PRT, string DerivedKey, string Context, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            string prtCookie = Helper.createPRTCookie(PRT, Context, DerivedKey, Proxy);
            string code = Helper.getCodeFromPRTCookie(prtCookie, Proxy, resourceID, clientID);
            result = authenticateWithCode(code, Proxy, clientID, resourceID);
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
            result = authenticateWithCode(code, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromPRTCookie(string PRTCookie, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            string code = Helper.getCodeFromPRTCookie(PRTCookie, Proxy, resourceID, clientID);
            result = authenticateWithCode(code, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromRefreshToken(string RefreshToken, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = authenticateWithRefreshToken(RefreshToken, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromRefreshTokenToTenant(string RefreshToken, string Tenant, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = authenticateWithRefreshTokenToTenant(RefreshToken, Tenant, Proxy, clientID, resourceID);
            return result;
        }


        public static string GetTokenFromUsernameAndPassword(string Username, string Password, string Proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894", string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = authenticateWithUserNameAndPassword(Username, Password, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenWithClientIDAndSecret(string ClientID, string ClientSecret, string Tenant, string Proxy, string resourceID = "https://graph.windows.net")
        {
            string result = null;
            result = authenticateWithClientIDandSecret(ClientID, ClientSecret, Tenant, Proxy, resourceID);
            return result;
        }

        public static string getToken(TokenOptions opts, string clientID = null, string resourceID = null)
        {
            string result = null;

            if (clientID == null && resourceID == null)
            {
                clientID = opts.ClientID;
                resourceID = opts.ResourceID;
            }

            if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = getTokenFromPRTAndDerivedKey(opts.PRT, opts.DerivedKey, opts.Context, opts.Proxy, clientID, resourceID);
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
                result = GetTokenFromRefreshToken(opts.RefreshToken, opts.Proxy, clientID, resourceID);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                result = GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Proxy, clientID, resourceID);
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

        public static string getTokenFromDe(TokenOptions opts)
        {
            string result = null;
            if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = getTokenFromPRTAndDerivedKey(opts.PRT, opts.DerivedKey, opts.Context, opts.Proxy, opts.ClientID, opts.ResourceID);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                result = GetTokenFromPRTAndSessionKey(opts.PRT, opts.SessionKey, opts.Proxy, opts.ClientID, opts.ResourceID);
            }
            else if (opts.PrtCookie != null)
            {
                result = GetTokenFromPRTCookie(opts.PrtCookie, opts.Proxy, opts.ClientID, opts.ResourceID);
            }
            else if (opts.RefreshToken != null)
            {
                result = GetTokenFromRefreshToken(opts.RefreshToken, opts.Proxy, opts.ResourceID, opts.ClientID);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                result = GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Proxy, opts.ClientID, opts.ResourceID);
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
