using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Models.User
{
    public class User
    {
        public string Username { get; set; }
        public uint PlayCount { get; set; }
        public string PasswordHash { get; set; }
        public string Salt { get; set; }
    }
}
