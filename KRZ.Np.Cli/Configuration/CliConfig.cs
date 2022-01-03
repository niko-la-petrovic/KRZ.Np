using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Configuration
{
    public class CaCert
    {
        public string FilePath { get; set; }
        public string Password { get; set; }
    }

    public class CliConfig
    {
        public const string SectionName = nameof(CliConfig);
        public CaCert RootCa { get; set; }
        public List<CaCert> CaCerts { get; set; }
        public DbConfig DbConfig { get; set; }
        public string CrlPath { get; set; }
        public QuestionsConfig QuestionsConfig { get; set; }
    }

    public class DbConfig
    {
        public string DbFile { get; set; }
        public string DbPasswordFile { get; set; }
    }

    public class QuestionsConfig
    {
        public string QuestionsPath { get; set; }
        public string FileRegex { get; set; }
    }
}
