using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Polymorph.Attributes;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Models
{
    [JsonBaseClass(DiscriminatorName = QuizItemDiscriminator.DiscriminatorName)]
    public abstract class QuizItem
    {
        public string Text { get; set; }
        public string Answer { get; set; }

        public bool IsCorrect(string answer)
        {
            return Answer == answer;
        }
    }
}
