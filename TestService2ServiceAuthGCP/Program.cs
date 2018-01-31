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
        private const string IAM_SCOPE = @"https://www.googleapis.com/auth/iam";
        private const string OAUTH_TOKEN_URI = 
            "https://www.googleapis.com/oauth2/v4/token";
        private static readonly string SERVICEACCOUNT_JSON_PATH =
            Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
        private const string SAMPLE_APP_URL = "https://{0}.appspot.com";

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

        private static string MakeIapRequest()
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
            string clientId = credentials.ClientId;
            string projectId = credentials.ProjectId;
            var privateKeyBytes = Encoding.ASCII.GetBytes(privateKey);

            // Request an OIDC token for the Cloud IAP-secured client ID

            // Generates a JWT signed with the service account's private key containing a special "target_audience" claim
            var jwtBasedAccessToken = CreateAccessToken(privateKeyBytes, clientId, email);
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
            var objects = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseContent);
            var token = objects["access_token"];

            // Include the OIDC token in an Authorization: Bearer header to IAP-secured resource
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            string response = httpClient.GetStringAsync(
                string.Format(SAMPLE_APP_URL, credentials.ProjectId)).Result;
            return response;
        }

        private static long ToUnixEpochDate(DateTime date)
              => (long)Math.Round((date.ToUniversalTime() -
                                   new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                                  .TotalSeconds);

        private static GoogleCredential GetCredential()
        {
            var credential = GoogleCredential.FromFile(
                SERVICEACCOUNT_JSON_PATH);
            credential = credential.CreateScoped(new string[] { IAM_SCOPE });
            
            return credential;
        }


        private static string CreateAccessToken(byte[] privateKey, 
            string iapClientId, string email)
        {
            var currentTime = ToUnixEpochDate(DateTime.Now);
            var expTime = ToUnixEpochDate(DateTime.Now.AddMinutes(10));

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
            var symmetricKey = new SymmetricSecurityKey(privateKey);

            var creds = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
