using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Models.Certs
{
    public class DistinguishedName
    {
        public string CommonName { get; set; }
        public string Organization { get; set; }
        public string OrganizationalUnit { get; set; }
        public string Locality { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string EmailAddress { get; set; }

        public static string Escape(string prefix, string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return null;

            return $"{prefix}={input.Replace(",", "\\2C")}";
        }

        public string GetDistinguishedName() =>
            string.Join(",", new List<string>() { Escape("CN", CommonName), Escape("O", Organization),
                Escape("OU", OrganizationalUnit), Escape("L",Locality), Escape("S",State),
                Escape("C", Country), Escape("E", EmailAddress) }.Where(s => !string.IsNullOrWhiteSpace(s)));
    }
}
