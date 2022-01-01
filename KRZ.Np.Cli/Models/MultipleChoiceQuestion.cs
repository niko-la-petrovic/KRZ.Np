using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Polymorph.Attributes;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Models
{
    [JsonSubClass(DiscriminatorValue = QuizItemDiscriminator.MultipleChoiceQuestion)]
    public class MultipleChoiceQuestion : QuizItem
    {
        public string[] Choices { get; set; }
    }
}
