using System.Text.Json.Polymorph.Attributes;

namespace KRZ.Np.Cli.Models.Quiz
{
    [JsonSubClass(DiscriminatorValue = QuizItemDiscriminator.MultipleChoiceQuestion)]
    public class MultipleChoiceQuestion : QuizItem
    {
        public string[] Choices { get; set; }
    }
}
