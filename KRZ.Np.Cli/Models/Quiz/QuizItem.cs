using System.Text.Json.Polymorph.Attributes;

namespace KRZ.Np.Cli.Models.Quiz
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
