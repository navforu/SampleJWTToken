using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JWT
{
  public static class JWT
  {
	static string ApiKey = "your-secret-key";
	static string ApiSecret = "YOUR_API_SECRET_HERE";
	static string ApiRole = "ROLE";
	static string ApiUser = "USER";
	static DateTime DefaultDate = new DateTime(1970, 1, 1);

    	#region GenerateToken
	internal static string GenerateToken()
    	{
		//Default to 5 mins.
		return GenerateToken(5);
    	}

	internal static string GenerateToken(long ExpiresInMinutes)
	{
		// Token will be good for mentioned minutes - Default 5 mins.
		DateTime Expiry = DateTime.UtcNow.AddMinutes(ExpiresInMinutes);

		int ts = (int)(Expiry - DefaultDate).TotalSeconds;

		// Create Security key  using private key above:
		var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ApiSecret));

		// length should be >256b
		var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

		//Finally create a Token
		var header = new JwtHeader(credentials);

		//Required Payload
		var payload = new JwtPayload
		{
			{ "Role", ApiRole },
			{ "iss", ApiKey },
			{ "Username", ApiUser },
			{ "exp", ts },
			{ "iat", (int)(DateTime.UtcNow - DefaultDate).TotalSeconds }
		};

		var secToken = new JwtSecurityToken(header, payload);
		var handler = new JwtSecurityTokenHandler();

		// Token to String so you can use it in your client
		var tokenString = handler.WriteToken(secToken);

		return tokenString;
	}
    	#endregion

    	#region Validate Token
	internal static bool ValidateToken(string authToken)
	{
		JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
		string accessToken = authToken.StartsWith("Bearer ") ? authToken.Substring(7) : authToken;

		JwtSecurityToken token = handler.CanReadToken(accessToken) ? handler?.ReadJwtToken(accessToken) : null ;

		//Default to DateTime.MinValue if the token is not JwtSecurityToken.
		DateTime tokenExpiryDate = token?.ValidTo != null ? token.ValidTo.ToUniversalTime() : DateTime.MinValue;

		bool isValidJwTToken;
		// If there is no valid `exp` claim then `ValidTo` returns DateTime.MinValue
		// If the token is in the past then you can't use it
		if (tokenExpiryDate == DateTime.MinValue ||
			tokenExpiryDate < DateTime.UtcNow ||
			!string.Equals(token.Issuer, ApiKey, StringComparison.OrdinalIgnoreCase)) // Verify the token issuer is the ApiKey
				isValidJwTToken = false;
		else
				isValidJwTToken = true;

		return isValidJwTToken;
	}
    	#endregion

    	#region ExpiresIn
	internal static int ExpiresInMinutes(string accessToken)
	{
		return ExpiresInSeconds(accessToken) / 60;
	}

	internal static int ExpiresInSeconds(string accessToken)
    	{
		JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
		JwtSecurityToken token = handler.CanReadToken(accessToken) ? handler?.ReadJwtToken(accessToken) : null;

		DateTime tokenExpiryDate = token?.ValidTo != null ? token.ValidTo.ToUniversalTime() : DefaultDate;
		
		int expiresIn = (int)(tokenExpiryDate - DateTime.Now.ToUniversalTime()).TotalSeconds;
		return expiresIn;
	}
    	#endregion
    
   }
}
