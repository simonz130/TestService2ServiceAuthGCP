using Google.Apis.Auth.OAuth2;
using Google.Apis.Json;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace TestService2ServiceAuthGCP
{
    class Program
    {
        const string IAM_SCOPE = @"https://www.googleapis.com/auth/iam";

        const string IAP_CLIENT_ID = 
            @"356971158591-hj00r99smbb37q831a4h4r0l63m105kj.apps.googleusercontent.com";
        const string OAUTH_TOKEN_URI = 
            "https://www.googleapis.com/oauth2/v4/token";
        static readonly string SERVICEACCOUNT_JSON_PATH =
            Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
        const string SAMPLE_APP_URL = "https://{0}.appspot.com";

        static void Main(string[] args)
        {
            var response = MakeIapRequest();
            Console.WriteLine(response);
        }

        class Credentials : JsonCredentialParameters
        {
            [JsonProperty("project_id")]
            public string ProjectId { get; set; }
        }

        class IapRequestResponse {
            [JsonProperty("id_token")]
            public string IdToken { get; set; }
        }

        static string MakeIapRequest()
        {
            Credentials credentials;
            // Generate JWT-based access token
            using (var fs = new FileStream(SERVICEACCOUNT_JSON_PATH, 
                FileMode.Open, FileAccess.Read))
            {
                credentials = NewtonsoftJsonSerializer.Instance
                    .Deserialize<Credentials>(fs);

            }
            string privateKey = credentials.PrivateKey;
            string email = credentials.ClientEmail;
            string projectId = credentials.ProjectId;

            // Request an OIDC token for the Cloud IAP-secured client ID

            // Generates a JWT signed with the service account's private key 
            // containing a special "target_audience" claim
            var jwtBasedAccessToken = 
                CreateAccessToken(privateKey, IAP_CLIENT_ID, email);
            //var req = new Google.Apis.Auth.OAuth2.Requests.TokenRequest();

            var body = new Dictionary<string, string>
            {
                { "assertion", jwtBasedAccessToken },
                { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"}
            };

            var httpClient = new HttpClient();
            var httpContent = new FormUrlEncodedContent(body);

            var result = httpClient.PostAsync(OAUTH_TOKEN_URI, httpContent).Result;
            var responseContent = result.Content.ReadAsStringAsync().Result;
            int statusCode = (int) result.StatusCode;
            if (statusCode < 200 || statusCode >= 300) 
            {
                throw new HttpRequestException(string.Format("{0} {1}\n{2}",
                    statusCode, result.ReasonPhrase, responseContent));
            }
            var token = JsonConvert.DeserializeObject<IapRequestResponse>(
                responseContent).IdToken;

            // Include the OIDC token in an Authorization: Bearer header to IAP-secured resource
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            string url = string.Format(SAMPLE_APP_URL, credentials.ProjectId);
            string response = httpClient.GetStringAsync(url).Result;
            return response;
        }

        static long ToUnixEpochDate(DateTime date)
              => (long)Math.Round((date.ToUniversalTime() -
                                   new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                                  .TotalSeconds);

        static GoogleCredential GetCredential()
        {
            var credential = GoogleCredential.FromFile(
                SERVICEACCOUNT_JSON_PATH);
            credential = credential.CreateScoped(new string[] { IAM_SCOPE });
            
            return credential;
        }


        static string CreateAccessToken(string privateKey, 
            string iapClientId, string email)
        {
            var now = DateTime.UtcNow;
            var currentTime = ToUnixEpochDate(now);
            var expTime = ToUnixEpochDate(now.AddMinutes(10));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Aud, OAUTH_TOKEN_URI),
                new Claim(JwtRegisteredClaimNames.Sub, email),
                new Claim(JwtRegisteredClaimNames.Iat, currentTime.ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, expTime.ToString()),
                new Claim(JwtRegisteredClaimNames.Iss, email),                

                // We need to add this
                new Claim("target_audience", iapClientId)
            };
            // Both the PHP and Java samples use RS256 for signing.
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-8
            // Samples:
            //   https://github.com/GoogleCloudPlatform/java-docs-samples/blob/master/iap/src/main/java/com/example/iap/BuildIapRequest.java
            //   https://github.com/GoogleCloudPlatform/php-docs-samples/blob/master/iap/src/make_iap_request.php

            SecurityKey key = new RsaSecurityKey(
                Pkcs8.DecodeRsaParameters(privateKey));
            var creds = new SigningCredentials(key, 
                SecurityAlgorithms.RsaSha256);
            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
