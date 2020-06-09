using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Tokens.Tests
{
    public class TokenData<THandler> : TokenData
        where THandler: SecurityTokenHandler, new()
    {
        public override SecurityTokenHandler Handler => new THandler();
    }

    public abstract class TokenData
    {
        private static readonly string CertificteBase64 = "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";
        public TokenData()
        {
            Xml = GenerateTokenXml();
        }

        public string Xml { get; }
        public Func<string, XmlReader> CreateReader { get; set; } = xml => XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        public abstract SecurityTokenHandler Handler { get; }
        public TokenValidationParameters TokenValidationParameters => new TokenValidationParameters
        {
            ClockSkew = TimeSpan.FromMinutes(5),
            IssuerSigningKeyResolver = (str, securityToken, _, __) =>
            {
                if (securityToken is SamlSecurityToken saml)
                    return GetIncludedSecurityKeys(saml.Assertion.Signature);
                if (securityToken is Saml2SecurityToken saml2)
                    return GetIncludedSecurityKeys(saml2.Assertion.Signature);

                return null;
            },
            ValidateActor = false,
            ValidateAudience = false,
            ValidateIssuer = false
        };

        private string GenerateTokenXml()
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(CertificteBase64));
            var key = new X509SecurityKey(certificate);

            var descriptor = new SecurityTokenDescriptor
            {
                Audience = "urn:test",
                Issuer = "urn:tester",
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(5),
                Subject = CreateIdentity("user")
            };

            var token = Handler.CreateToken(descriptor);
            return Handler.WriteToken(token);
        }

        private ClaimsIdentity CreateIdentity(string username)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Name, username)
            };
            return new ClaimsIdentity(claims, Handler.GetType().Name, ClaimTypes.NameIdentifier, ClaimTypes.Role);
        }
        private IEnumerable<SecurityKey> GetIncludedSecurityKeys(Signature signature)
        {
            if (signature?.KeyInfo == null) return null;
            return signature
                .KeyInfo
                .X509Data
                .SelectMany(data => data.Certificates)
                .Select(base64 => Convert.FromBase64String(base64))
                .Select(raw => new X509Certificate2(raw))
                .Select(cert => new X509SecurityKey(cert))
                .ToArray()
            ;
        }
    }
}
