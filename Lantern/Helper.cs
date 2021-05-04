using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace Lantern
{
    class Helper
    {
        public static string getCodeFromPRTCookie(string cookie, string proxy, string resourceID = "https://graph.windows.net", string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
        {
            String uri = string.Format(@"/Common/oauth2/authorize?resource={0}&client_id={1}&response_type={2}&haschrome={3}&redirect_uri={4}&client-request-id={5}&x-client-SKU={6}&x-client-Ver={7}&x-client-CPU={8}&x-client-OS={9}&site_id={10}&mscrid={11}",
                resourceID,
                clientID,
                "code",
                "1",
                "urn:ietf:wg:oauth:2.0:oob",
                //Guid.NewGuid(),
                "AAAAAAA",
                "PCL.Desktop",
                "3.19.7.16602",
                "x64",
                "Microsoft Windows NT 10.0.19569.0",
                "501358",
                Guid.NewGuid());
            HttpClient client = getDefaultClient(proxy);
            using (client)
            {
                var message = new HttpRequestMessage(HttpMethod.Get, uri);
                String xcookie = "x-ms-RefreshTokenCredential=" + cookie;
                message.Headers.Add("Cookie", xcookie);
                var response = client.SendAsync(message).Result;
                if (response.StatusCode.Equals("200"))
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }

                string location = "";

                if (response.Headers.Contains("Location"))
                {
                    location = response.Headers.Location.ToString();
                }
                else
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return "";
                }

                int startOf = location.IndexOf("code=");
                if (startOf == -1)
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }
                int endOf = location.IndexOf("&", startOf + 5);
                int len = endOf - startOf;
                string code = location.Substring(startOf + 5, len - 5);
                client.Dispose();
                return code;
            }
        }

        public static HttpClient getDefaultClient(String proxy = null, bool useCookies = true, String baseAdress = "https://login.microsoftonline.com")
        {
            HttpClientHandler handler = new HttpClientHandler();
            if (proxy != null)
            {
                handler.Proxy = new WebProxy(proxy);
                handler.UseProxy = true;
            }

            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                };
            handler.AllowAutoRedirect = false;

            handler.UseCookies = useCookies;
            var client = new HttpClient(handler);
            client.BaseAddress = new Uri(baseAdress);
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("UA-CPU", "AMD64");
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)");
            return client;

        }

        public static string addNewDeviceToAzure(string proxy, string accesstoken, string certificaterequest, string transportKey, string targetDomain, string deviceDisplayName, bool registerDevice)
        {
            using(var client = getDefaultClient(proxy, false, "https://enterpriseregistration.windows.net"))
            using (var message = new HttpRequestMessage(HttpMethod.Post, "/EnrollmentServer/device/?api-version=1.0"))
            {
                //message.Headers.Add("Authorization", "Bearer " + accesstoken);
                message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accesstoken);
                message.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");

                int jointype = 0;
                if (registerDevice)
                {
                    jointype = 4;
                }

                Dictionary<string, object> body = new Dictionary<string, object>
                {
                    { "TransportKey", transportKey },
                    { "JoinType", jointype },
                    { "DeviceDisplayName", deviceDisplayName },
                    {  "OSVersion", "10.0.19041.804" },
                    { "CertificateRequest" , new Dictionary<string,string>{
                        {"Type", "pkcs10" },
                        {"Data", certificaterequest }
                    }},
                    { "TargetDomain", targetDomain },
                    { "DeviceType", "Windows" },
                    { "Attributes" , new Dictionary<string,bool>{
                        {"ReuseDevice", true },
                        {"ReturnClientSid", true },
                        {"SharedDevice", false }
                    }},

                };
                var content = new StringContent(JsonConvert.SerializeObject(body, Formatting.Indented));
                message.Content = content;
                var response = client.SendAsync(message).Result;
                if (response.IsSuccessStatusCode)
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    return result;
                }
            }
            return "";
        }

        public static string postToTokenEndpoint(FormUrlEncodedContent formContent, string proxy, string tenant = null)
        {
            string uri = "/common/oauth2/token";
            if (tenant != null)
            {
                uri = "/" + tenant + "/oauth2/token";
            }
            using (var message = new HttpRequestMessage(HttpMethod.Post, uri))
            using (var client = getDefaultClient(proxy, false))
            {
                message.Headers.Add("client-request-id", Guid.NewGuid().ToString());
                message.Headers.Add("return-client-request-id", "true");
                message.Content = formContent;
                var response = client.SendAsync(message).Result;
                if (response.IsSuccessStatusCode)
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    return result;
                }
                return null;
            }
        }

        public static string authenticateWithClientIDandSecret(string clientID, string clientSecret, string tenant, string proxy, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>(ressourceId, ressourceId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
            return postToTokenEndpoint(formContent, proxy, tenant);
        }

        public static string authenticateWithUserNameAndPassword(string username, string password, string proxy, string ressourceId, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
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
            return postToTokenEndpoint(formContent, proxy);
        }

        public static string getAccessTokenWithRefreshtoken(string refreshToken, string ressourceId, string tenant, string proxy, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
            return postToTokenEndpoint(formContent, proxy, tenant);
        }

        public static string authenticateWithRefreshToken(string token, string proxy, string ressourceId, string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("refresh_token", token),
                });
            return postToTokenEndpoint(formContent, proxy);
        }
        public static string authenticateWithCode(string code, string proxy, string ressourceId = "https://graph.windows.net", string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
                new KeyValuePair<string, string>("code", code)
                });

            return postToTokenEndpoint(formContent, proxy);
        }

        // https://stackoverflow.com/questions/1459006/is-there-a-c-sharp-equivalent-to-pythons-unhexlify
        public static byte[] Hex2Binary(string hex)
        {
            var chars = hex.ToCharArray();
            var bytes = new List<byte>();
            for (int index = 0; index < chars.Length; index += 2)
            {
                var chunk = new string(chars, index, 2);
                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
            }
            return bytes.ToArray();
        }

        //https://stackoverflow.com/questions/1228701/code-for-decoding-encoding-a-modified-base64-url
        public static byte[] Base64Decode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception(
             "Illegal base64prt string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        public static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        public static string createPRTCookie(string prt, string context, string derived_sessionkey, string proxy)
        {
            string secret = derived_sessionkey.Replace(" ", "");
            string nonce = getNonce(proxy);

            byte[] data = Base64Decode(prt);

            string prtdecoded = Encoding.UTF8.GetString(data);

            var payload = new Dictionary<string, object>
            {
                { "refresh_token", prtdecoded },
                { "is_primary", "true" },
                { "request_nonce", nonce }
            };

            var header = new Dictionary<string, object>
            {
                { "ctx", Hex2Binary(context) }
            };

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var sdata = Hex2Binary(secret);
            var cookie = encoder.Encode(header, payload, sdata);
            return cookie;
        }

        public static String getNonce(string proxy)
        {
            using (var client = getDefaultClient(proxy))
            {
                // Original from auth.py
                //String uri = string.Format(@"/Common/oauth2/authorize?resource={0}&client_id={1}&response_type={2}&haschrome={3}&redirect_uri={4}&client-request-id={5}&x-client-SKU={6}&x-client-Ver={7}&x-client-CPU={8}&x-client-OS={9}&site_id={10}&mscrid={11}",
                //    "https://graph.windows.net/",
                //    "1b730954-1685-4b74-9bfd-dac224a7b894",
                //    "code",
                //    "1",
                //    "urn:ietf:wg:oauth:2.0:oob",
                //    Guid.NewGuid(),
                //    "PCL.Desktop",
                //    "3.19.7.16602",
                //    "x64",
                //    "Microsoft Windows NT 10.0.19569.0",
                //    "501358",
                //    Guid.NewGuid());


                String uri = string.Format(@"/Common/oauth2/authorize?client_id={0}", "1b730954-1685-4b74-9bfd-dac224a7b894");
                var response = client.GetAsync(uri).Result;
                var responseContent = response.Content;
                string responseString = responseContent.ReadAsStringAsync().Result;
                int startOf = responseString.IndexOf("\"nonce\":\"");
                int endOf = responseString.IndexOf("\"", startOf + 9);
                int len = endOf - startOf;
                string nonce = responseString.Substring(startOf + 9, len - 9);
                client.Dispose();
                return nonce;
            }
        }

        public static string getNonce2(string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "srv_challenge")
                });
            string result = postToTokenEndpoint(formContent, proxy);
            JToken parsedNonce = JToken.Parse(result);
            return parsedNonce["Nonce"].ToString();
        }

        public static string getTenantFromAccessToken(string accesstoken)
        {
            return getInfoFromBase64JSON(accesstoken, "tid");
        }

        public static string getAudienceFromAccessToken(string accesstoken)
        {
            return getInfoFromBase64JSON(accesstoken, "aud");
        }
        public static string getUPNFromAccessToken(string accesstoken)
        {
            return getInfoFromBase64JSON(accesstoken, "upn");
        }

        public static string getInfoFromBase64JSON(string jsonString, string info)
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            string decodedaccesstoken = decoder.Decode(jsonString);
            JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
            return parsedAccessToken[info].ToString();
        }

        public static byte[] GetByteArray(int size)
        {
            Random rnd = new Random();
            byte[] b = new byte[size]; // convert kb to byte
            rnd.NextBytes(b);
            return b;
        }

        public static string derivedKeys(string sessionKey, string ctx)
        {
            return "";
        }

        public static string getToken(TokenOptions opts, string resourceID = "https://graph.windows.net", string clientID = "1b730954-1685-4b74-9bfd-dac224a7b894")
        {
            string result = null;
            if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                string prtCookie = createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy);
                string code = getCodeFromPRTCookie(prtCookie, opts.Proxy, resourceID, clientID);
                result = authenticateWithCode(code, opts.Proxy, resourceID, clientID);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            { 

            }
            else if (opts.PrtCookie != null)
            {
                string code = getCodeFromPRTCookie(opts.PrtCookie, opts.Proxy);
                result = authenticateWithCode(code, opts.Proxy);


            }
            else if (opts.RefreshToken != null)
            {
                result = authenticateWithRefreshToken(opts.RefreshToken, opts.Proxy, opts.ResourceID);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                if (resourceID != null)
                {
                    result = authenticateWithUserNameAndPassword(opts.UserName, opts.Password, opts.Proxy, resourceID, clientID);
                }
                else
                {
                    result = authenticateWithUserNameAndPassword(opts.UserName, opts.Password, opts.Proxy, opts.ResourceID);
                }
                
            }
            else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
            {
                result = authenticateWithClientIDandSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy, opts.ResourceID);
            }
            else
            {
                Console.WriteLine("Please set the corect arguments.");
                return null;
            }
            return result;

        }
    }
}
