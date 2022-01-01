using CommandLine;
using KRZ.Np.Cli.Models;
using KRZ.Np.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Polymorph.Extensions;

namespace KRZ.Np.Cli
{
    public class Program
    {
        public class Options
        {
            [Option('e', "encode", Required = false, HelpText = "Apply steganography to encode a string into an image.", Default = false)]
            public bool IsSteganography { get; set; }

            [Option('s', "source", Required = false, HelpText = "Source file.")]
            public string SourceFilePath { get; set; }

            [Option('i', "input", Required = false, HelpText = "Input string to use.")]
            public string Input { get; set; }

            [Option('r', "read", Required = false, HelpText = "Whether to decode the source image.", Default = false)]
            public bool ShouldRead { get; set; }

            [Option('q', "question", Required = false, HelpText = "Whether to try to deserialize an array of questions from JSON.")]
            public bool IsQuestion { get; set; }
        }

        static void Main(string[] args)
        {
            var parser = Parser.Default;
            var parserResult = parser
                .ParseArguments<Options>(args);

            parserResult.WithParsed(o =>
            {
                if (o.IsSteganography || o.ShouldRead)
                    ProcessSteganographyArguments(o);
                if (o.IsQuestion)
                    ProcessQuestions(o);
            });
            parserResult.WithNotParsed(o =>
            {
                Console.WriteLine("Use --help.");
            });
        }

        private static void ProcessQuestions(Options o)
        {
            var srcFilePath = o.SourceFilePath;
            string json = File.ReadAllText(srcFilePath);
            var options = new JsonSerializerOptions { };
            options.AddDiscriminatorConverterForHierarchy<QuizItem>(QuizItemDiscriminator.DiscriminatorName);
            var result = JsonSerializer.Deserialize<List<QuizItem>>(json, options);
            Console.WriteLine(JsonSerializer.Serialize(result));
        }

        private static void ProcessSteganographyArguments(Options options)
        {
            var input = options.Input;
            var filePath = options.SourceFilePath;

            if (options.ShouldRead)
            {
                var decoded = Steganography.DecodeBmp(filePath);
                Console.WriteLine(decoded);
            }
            else
            {
                var toEncode = Encoding.Default.GetBytes(input);
                var destinationPath = Steganography.EncodeBmp(filePath, toEncode);
            }
        }
    }
}

