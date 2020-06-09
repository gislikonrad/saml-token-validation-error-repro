using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Xml.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Tokens.Tests
{
    public class ValidationTests
    {
        private ITestOutputHelper _output;
        public ValidationTests(ITestOutputHelper output)
        {
            IdentityModelEventSource.ShowPII = true;
            _output = output;
        }

        [Theory]
        [MemberData(nameof(ShouldValidateTokenData))]
        public void ShouldValidateToken(TokenData data)
        {
            _output.WriteLine(data.Xml);
            var reader = data.CreateReader(data.Xml);
            Assert.True(data.Handler.CanReadToken(reader));

            data.Handler.ValidateToken(reader, data.TokenValidationParameters, out _);
        }

        public static TheoryData<TokenData> ShouldValidateTokenData = new TheoryData<TokenData>
        {
            new TokenData<SamlSecurityTokenHandler>(),
            new TokenData<SamlSecurityTokenHandler>
            {
                CreateReader = xml => XDocument.Parse(xml).CreateReader()
            },

            new TokenData<Saml2SecurityTokenHandler>(),
            new TokenData<Saml2SecurityTokenHandler>
            {
                CreateReader = xml => XDocument.Parse(xml).CreateReader()
            }
        };
    }
}
