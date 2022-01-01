using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Models
{
    public static class QuizItemDiscriminator
    {
        public const string DiscriminatorName = "TypeDiscriminator";
        public const string FreeQuestion = nameof(FreeQuestion);
        public const string MultipleChoiceQuestion = nameof(MultipleChoiceQuestion);
    }
}
