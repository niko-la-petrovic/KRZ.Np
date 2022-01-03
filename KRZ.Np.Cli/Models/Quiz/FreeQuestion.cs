using System.Text.Json.Polymorph.Attributes;

namespace KRZ.Np.Cli.Models.Quiz
{
    [JsonSubClass(DiscriminatorValue = QuizItemDiscriminator.FreeQuestion)]
    public class FreeQuestion : QuizItem
    {
        public override string OfferedAnswerText => "";
    }
}
