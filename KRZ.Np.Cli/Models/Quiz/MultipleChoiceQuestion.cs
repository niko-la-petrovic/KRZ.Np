using System;
using System.Text.Json.Polymorph.Attributes;

namespace KRZ.Np.Cli.Models.Quiz
{
    [JsonSubClass(DiscriminatorValue = QuizItemDiscriminator.MultipleChoiceQuestion)]
    public class MultipleChoiceQuestion : QuizItem
    {
        public string[] Choices { get; set; }

        public override bool IsCorrect(string answer)
        {
            try
            {
                int index = Convert.ToInt32(answer);

                return Choices[index - 1] == Answer;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public override string OfferedAnswerText
        {
            get
            {
                string toReturn = "";

                for (int i = 0; i < Choices.Length; i++)
                {
                    toReturn += $"{i + 1}: {Choices[i]}{Environment.NewLine}";
                }

                return toReturn;
            }
        }
    }
}
