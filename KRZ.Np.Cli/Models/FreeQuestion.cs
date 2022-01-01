using System.Text.Json.Polymorph.Attributes;

namespace KRZ.Np.Cli.Models
{
    [JsonSubClass(DiscriminatorValue = QuizItemDiscriminator.FreeQuestion)]
    public class FreeQuestion : QuizItem
    {
    }
}
