namespace KRZ.Np.Cli.Models.Quiz
{
    public static class QuizItemDiscriminator
    {
        public const string DiscriminatorName = "TypeDiscriminator";
        public const string FreeQuestion = nameof(FreeQuestion);
        public const string MultipleChoiceQuestion = nameof(MultipleChoiceQuestion);
    }
}
