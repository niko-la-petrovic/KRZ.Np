using System.Text.Json.Polymorph.Attributes;
using System.Text.Json.Serialization;

namespace KRZ.Np.Cli.Models.Quiz
{
    [JsonBaseClass(DiscriminatorName = QuizItemDiscriminator.DiscriminatorName)]
    public abstract class QuizItem
    {
        public string Text { get; set; }
        public string Answer { get; set; }

        [JsonIgnore]
        public abstract string OfferedAnswerText { get; }

        public virtual bool IsCorrect(string answer)
        {
            return Answer == answer;
        }
    }
}
