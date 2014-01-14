using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWT
{
    using System.IdentityModel.Protocols.WSTrust;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel.Security.Tokens;

    class Program
    {
        static void Main(string[] args)
        {
            // You can generate a random key if you like
            RunWithRandomKey();
            // Or you can do all of this fun stuff w/ a pre-shared key that you store in the web.configs of your trusted sites
            // -- storing in web.config would allow you to rotate shared keys on some regular interval w/o having to 
            // build a service to go fetch the key from a database/memory cache - perhaps monthly during a maintenance window?
            RunWithPreSharedKey("Us33C6Axe4Ik2QZH86u68h3cEUMiO3NI");
        }

        static void RunWithRandomKey()
        {
            Console.WriteLine("Running with a randomly generated key");
            var aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey();
            Console.WriteLine(String.Format("Your random key is: {0}", System.Text.Encoding.Default.GetString(aes.Key)));

            var tokenString = CreateToken(aes.Key);
            var principal = ValidateToken(tokenString, aes.Key);

            System.Diagnostics.Debug.Assert(principal.Identities.First().Claims.Any(c => c.Type == "UserToImpersonate" && c.Value == "Donor.12.James"));
            foreach (var claim in principal.Claims)
            {
                Console.WriteLine("Claim {0} value => {1}", claim.Type, claim.Value);
            }
            Console.WriteLine("Press any key to continue...");
            Console.ReadLine();
        }

        static void RunWithPreSharedKey(string key)
        {
            Console.WriteLine("Running with the pre-shared key of " + key);
            var bKey = ByteMyKey(key);
            var tokenString = CreateToken(bKey);
            var principal = ValidateToken(tokenString, bKey);

            System.Diagnostics.Debug.Assert(principal.Identities.First().Claims.Any(c => c.Type == "UserToImpersonate" && c.Value == "Donor.12.James"));
            foreach (var claim in principal.Claims)
            {
                Console.WriteLine("Claim {0} value => {1}", claim.Type, claim.Value);
            }
            Console.WriteLine("Press any key to continue...");
            Console.ReadLine();
        }

        static byte[] ByteMyKey(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        static string CreateToken(byte[] key)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var securityKey = new InMemorySymmetricSecurityKey(key);


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, "Truist.dt"),
                        new Claim("UserToImpersonate", "Donor.12.James"), 
                    }),
                TokenIssuerName = "Truist",
                AppliesToAddress = "http://www.truist.com",
                Lifetime = new Lifetime(now, now.AddMinutes(2)),
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest)
            };



            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            string tokenString = tokenHandler.WriteToken(token);
            Console.WriteLine();
            Console.WriteLine("And here's ze token");
            Console.WriteLine(tokenString);
            Console.WriteLine();
            return tokenString;
        }

        static ClaimsPrincipal ValidateToken(string tokenString, byte[] key)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = "Truist",
                AllowedAudience = "http://www.truist.com",
                SigningToken = new BinarySecretSecurityToken(key)
            };

            var principal = tokenHandler.ValidateToken(
                new JwtSecurityToken(tokenString), validationParameters);

            return principal;
        }
    }
}
