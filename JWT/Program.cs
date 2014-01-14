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

	class Program
	{
		static void Main(string[] args)
		{

			var cert = new X509Certificate2();
			var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);

			cert = store.Certificates[0];
			var tokenString = CreateToken(cert);
			var principal = ValidateToken(cert, tokenString);
			//new X509RawDataKeyIdentifierClause(cert.RawData), tokenString);


		}

		static string CreateToken(X509Certificate2 cert)
		{
			var now = DateTime.UtcNow;
			var tokenHandler = new JwtSecurityTokenHandler();
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
				SigningCredentials = new X509SigningCredentials(cert)
			};

			SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
			string tokenString = tokenHandler.WriteToken(token);

			return tokenString;
		}

		static ClaimsPrincipal ValidateToken(X509Certificate2 cert, string tokenString)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var token = new X509SecurityToken(cert); 
			var validationParameters = new TokenValidationParameters()
			{
				ValidIssuer = "Truist",
				AllowedAudience = "http://www.truist.com",
				SigningToken = token
			};

			var principal = tokenHandler.ValidateToken(
				new JwtSecurityToken(tokenString), validationParameters);

			return principal;
		}
	}
}
