﻿using CommandLine;
using KRZ.Np.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Polymorph.Extensions;
using KRZ.Np.Cli.Models.Quiz;
using KRZ.Np.Cli.Models.User;
using System.Security.Cryptography.X509Certificates;
using KRZ.Np.Cli.Models.Certs;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using KRZ.Np.Cli.Configuration;
using KRZ.Np.Cli.Extensions;
using System.Linq;
using KRZ.Np.Cli.Utility;
using System.Text.RegularExpressions;

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

            [Option('g', "game", Required = false, HelpText = "Whether to play the game.")]
            public bool IsGame { get; set; }

            [Option(longName: "gen-root-ca", Required = false, HelpText = "Whether to gen the root CA.")]
            public bool IsGenRootCa { get; set; }

            [Option(longName: "gen-ca", Required = false, HelpText = "Whether to gen the CA.")]
            public bool IsGenCa { get; set; }

            [Option('p', "password", Required = false, HelpText = "The password to use.")]
            public string Password { get; set; }
        }

        private const int toAskCount = 5;
        static IConfiguration configuration;
        static readonly Random random = new();
        static CliConfig cliConfig;
        static void Main(string[] args)
        {
            configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddCommandLine(args)
                .Build();

            cliConfig = configuration.GetSection(CliConfig.SectionName).Get<CliConfig>();

            var parser = Parser.Default;
            var parserResult = parser
                .ParseArguments<Options>(args);

            parserResult.WithParsed(o =>
            {
                if (o.IsSteganography || o.ShouldRead)
                    ProcessSteganographyArguments(o);
                if (o.IsQuestion)
                    ProcessQuestions(o);
                if (o.IsGame)
                    ProcessGame(o);
                if (o.IsGenRootCa)
                    ProcessRootCa(o);
                if (o.IsGenCa)
                    ProcessCa(o);
            });
            parserResult.WithNotParsed(o =>
            {
                Console.WriteLine("Use --help.");
            });
        }

        private static void ProcessCa(Options o)
        {
            var rootCaCert = new X509Certificate2(o.SourceFilePath, o.Password,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
            using var cert = GenCert(parentCert: rootCaCert, saveCert: true, isUser: false);
        }

        private static void ProcessRootCa(Options o)
        {
            using var cert = GenCert(parentCert: null, saveCert: true, installCert: true);
        }

        private static void ProcessGame(Options o)
        {
            var quizItems = LoadQuizItems();

            var caCertConfig = cliConfig.CaCerts[random.Next(cliConfig.CaCerts.Count)];
            var caCert = new X509Certificate2(caCertConfig.FilePath, caCertConfig.Password,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);

            var db = GetDb();

            bool finished = false;
            User user = null;
            using var sha = SHA256.Create();
            do
            {
                Console.WriteLine();
                Console.Write("Would you like to register (y/n)?");
                string register = Console.ReadLine();
                bool shouldRegister = register == "y";
                if (!shouldRegister)
                    Console.WriteLine("Login");
                else
                    Console.WriteLine($"Registration");

                var creds = GetCredentials();
                if (creds.Password.Length < 3)
                {
                    Console.WriteLine("Password is too short.");
                    continue;
                }

                user = db.Users.FirstOrDefault(dc => dc.Username == creds.Username);
                if (shouldRegister)
                {
                    if (user is not null)
                    {
                        Console.WriteLine("Username is already in use.");
                        continue;
                    }

                    using var _ = GenCert(parentCert: caCert, isUser: true, ski: creds.Username);

                    var saltBytes = Salt.GetSalt();
                    var saltBase64 = Convert.ToBase64String(saltBytes);
                    var hashedPassword = sha.ComputeHash(Encoding.Default.GetBytes(creds.Password));
                    using var hashStream = new MemoryStream();
                    hashStream.Write(hashedPassword);
                    hashStream.Write(saltBytes);
                    var passwordHash = sha.ComputeHash(hashStream.ToArray());
                    var passwordHashBase64 = Convert.ToBase64String(passwordHash);

                    user = new User
                    {
                        Username = creds.Username,
                        PlayCount = 0,
                        Salt = saltBase64,
                        PasswordHash = passwordHashBase64
                    };

                    db.Users.Add(user);
                    SaveDb(db);

                    continue;
                }

                if (user is null)
                {
                    Console.WriteLine("Invalid credentials.");
                    continue;
                }
                bool validCreds = CheckPassword(sha, creds, user);
                if (!validCreds)
                {
                    Console.WriteLine("Invalid credentials.");
                    continue;
                }

                Console.Write("Specify your digital certificate:");
                string userCertPath = Console.ReadLine();
                X509Certificate2 userCert;
                try
                {
                    userCert = new X509Certificate2(userCertPath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    continue;
                }

                // todo check CRL

                if (user.PlayCount == 3)
                {
                    // todo revoke cert
                    continue;
                }

                var subjectKey = userCert.Extensions.Cast<X509Extension>().FirstOrDefault(ext => ext?.Oid.Value == X509AuthorityKeyIdentifierExtension.SubjectKeyIdentifierOid.Value) as X509SubjectKeyIdentifierExtension;
                // TODO make into method, replace other uses
                var userSki = Convert.ToHexString(Encoding.Default.GetBytes(creds.Username));
                if (subjectKey.SubjectKeyIdentifier != userSki)
                {
                    Console.WriteLine("You do not own this certificate.");
                    continue;
                }

                Console.WriteLine("Successful login.");
                finished = true;
            } while (!finished);

            int correctAnswers = PlayQuiz(quizItems);
            int score = (int)(((double)correctAnswers) / toAskCount * 100);
            var currentDateTime = DateTime.Now;

            user.PlayCount++;
            // TODO check if PlayCount >= 3 -> revoke user cert
            SaveDb(db);

            Console.WriteLine();
            Console.WriteLine($"[{currentDateTime}]: Your score is {score}/100.");
            var playScore = new PlayScore { DateTime = currentDateTime, Score = score, Username = user.Username };

            // TODO save score to file

            Console.Write("Check other users' scores (y/n)?");
            var checkScore = Console.ReadLine();
            if (checkScore == "y")
                return; // TODO read score file

        }

        private static int PlayQuiz(List<QuizItem> quizItems)
        {
            int correctAnswers = 0;
            for (int i = 0; i < toAskCount; i++)
            {
                Console.WriteLine($"Question {i + 1}/{toAskCount}");
                int itemIndex = random.Next(quizItems.Count);
                var quizItem = quizItems[itemIndex];
                Console.WriteLine(quizItem.Text);
                Console.WriteLine(quizItem.OfferedAnswerText);
                Console.Write("Answer:");
                var answer = Console.ReadLine();
                var isCorrect = quizItem.IsCorrect(answer);

                if (isCorrect)
                    correctAnswers++;

                Console.WriteLine();
            }

            return correctAnswers;
        }

        private static List<QuizItem> LoadQuizItems()
        {
            Console.WriteLine("Loading...");
            var questionsPath = cliConfig.QuestionsConfig.QuestionsPath;
            var questionsRegex = cliConfig.QuestionsConfig.FileRegex;
            var questionFiles = Directory.GetFiles(questionsPath)
                .Where(f => Regex.IsMatch(f, questionsRegex));
            var quizItems = questionFiles
                .Select(f => Steganography.DecodeBmp(f))
                .AsParallel()
                .Select(json => JsonSerializer.Deserialize<QuizItem>(json, QuestionsJsonSerializerOptions()))
                .ToList();
            Console.WriteLine($"Finished loading {quizItems.Count} quiz items.");
            Console.WriteLine();
            return quizItems;
        }

        private static X509Certificate2 GetRootCa()
        {
            return new X509Certificate2(cliConfig.RootCa.FilePath, cliConfig.RootCa.Password,
                                    X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
        }

        private static bool CheckPassword(SHA256 sha, Credentials creds, User user)
        {
            var hashedPassword = sha.ComputeHash(Encoding.Default.GetBytes(creds.Password));
            using var hashStream = new MemoryStream();
            var saltBytes = Convert.FromBase64String(user.Salt);
            hashStream.Write(hashedPassword);
            hashStream.Write(saltBytes);
            var passwordHash = sha.ComputeHash(hashStream.ToArray());
            var passwordHashBase64 = Convert.ToBase64String(passwordHash);

            bool validCreds = passwordHashBase64 == user.PasswordHash;
            return validCreds;
        }

        private static Db GetDb()
        {
            using var rootCa = GetRootCa();
            var db = GetDb(rootCa, cliConfig.DbConfig.DbPasswordFile, cliConfig.DbConfig.DbFile);
            return db;
        }
        private static Db GetDb(X509Certificate2 rootCa, string passwordFilePath, string dataFilePath)
        {
            Db db;
            if (!File.Exists(dataFilePath))
            {
                db = new Db { Users = new List<User>() };
                SaveDb(db);
            }
            else
            {
                var json = CryptoReadJson(rootCa, passwordFilePath, dataFilePath);
                db = JsonSerializer.Deserialize<Db>(json);
            }

            return db;
        }

        private static string CryptoReadJson(X509Certificate2 rootCa, string passwordFilePath, string dataFilePath)
        {
            var pfsBytes = File.ReadAllBytes(passwordFilePath);
            using var rsa = rootCa.GetRSAPrivateKey();
            var decryptedRsa = rsa.Decrypt(pfsBytes, RSAEncryptionPadding.Pkcs1);
            using var reader = new BinaryReader(new MemoryStream(decryptedRsa));
            var iv = reader.ReadBytes(16);
            var keySize = reader.ReadInt32() / 8;
            var key = reader.ReadBytes(keySize);

            var dBytes = File.ReadAllBytes(dataFilePath);
            var json = AesUtil.DecryptAes(dBytes, key, iv);
            return json;
        }

        private static void CryptoWriteJson(
            object obj, string passwordFilePath, string dataFilePath)
        {
            using var aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
            using var memStream = new MemoryStream();
            using var writer = new BinaryWriter(memStream);
            writer.Write(aes.IV);
            writer.Write(aes.KeySize);
            writer.Write(aes.Key);
            var toEncrypt = memStream.ToArray();

            using var rootCa = GetRootCa();
            var rsaParam = rootCa.GetRSAPublicKey().ExportParameters(false);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParam);
            var encrypted = rsa.Encrypt(toEncrypt, RSAEncryptionPadding.Pkcs1);
            using var pfs = File.OpenWrite(passwordFilePath);
            pfs.Write(encrypted);

            string json = JsonSerializer.Serialize(obj);
            using var dfs = File.OpenWrite(dataFilePath);
            var encryptedBytes = AesUtil.EncryptAes(json, aes.Key, aes.IV);
            dfs.Write(encryptedBytes);
        }

        private static void SaveDb(Db db)
        {
            CryptoWriteJson(db, cliConfig.DbConfig.DbPasswordFile, cliConfig.DbConfig.DbFile);
        }

        // TODO create CRL if doesn't exist
        // TODO add CRL to CA
        // TDOo add CRL to user cert
        private static X509Certificate2 GenCert(
            X509Certificate2 parentCert = null,
            bool saveCert = true,
            bool installCert = true,
            bool isUser = false,
            string ski = null)
        {
            bool selfSigned = parentCert is null;

            string country, emailAddress, state, locality, organization, organizationalUnit,
                commonName;
            Console.Write("Country Name (2 letter code):");
            country = Console.ReadLine();
            Console.Write("State or Province Name (full name):");
            state = Console.ReadLine();
            Console.Write("Locality Name (e.g. city):");
            locality = Console.ReadLine();
            Console.Write("Organization Name(e.g. company):");
            organization = Console.ReadLine();
            Console.Write("Organizational Unit Name (e.g. section):");
            organizationalUnit = Console.ReadLine();
            Console.Write("Common Name (e.g. server FQDN or your name):");
            commonName = Console.ReadLine();
            Console.Write("Email Address:");
            emailAddress = Console.ReadLine();

            var distinguishedName = new DistinguishedName
            {
                CommonName = commonName,
                Country = country,
                EmailAddress = emailAddress,
                State = state,
                Locality = locality,
                Organization = organization,
                OrganizationalUnit = organizationalUnit,
            };
            var dnString = distinguishedName.GetDistinguishedName();
            var x500distinguishedName = new X500DistinguishedName(dnString, X500DistinguishedNameFlags.UseCommas);

            using var rsa = RSA.Create(2048);

            var request = new CertificateRequest(x500distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var keyUsageFlags = X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment
                | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
            if (!isUser)
                keyUsageFlags |= X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyAgreement;
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsageFlags, true));

            request.CertificateExtensions.Add(
               new X509EnhancedKeyUsageExtension(
                   new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            if (selfSigned)
            {
                SubjectAlternativeNameBuilder sanBuilder = new();
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddDnsName(Environment.MachineName);
                sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);

                request.CertificateExtensions.Add(sanBuilder.Build());

                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, true, 1, true));
            }
            else if (!isUser)
            {
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, true, 0, true));
            }
            else
            {
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, true));
            }
            var skiString = ski ?? commonName;
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(Convert.ToHexString(Encoding.Default.GetBytes(skiString)), true));
            if (parentCert is not null)
                request.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(parentCert, false));

            var notBefore = new DateTimeOffset(DateTime.UtcNow.AddDays(-1));
            var notAfter = parentCert?.NotAfter.AddDays(-1) ?? new DateTimeOffset(DateTime.UtcNow.AddDays(3650));

            var untrimmedSerial = Guid.NewGuid().ToString().Replace("-", "");
            var serialNumberBytes = Encoding.Default.GetBytes(untrimmedSerial).AsSpan().Slice(0, 8).ToArray();

            X509Certificate2 certificate;
            if (selfSigned)
                certificate = request.Create(
                    x500distinguishedName,
                    X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
                    notBefore, notAfter, serialNumberBytes);
            else
                certificate = request.Create(
                    parentCert,
                    notBefore,
                    notAfter,
                    Encoding.Default.GetBytes(Guid.NewGuid().ToString()).AsSpan().Slice(0, 8).ToArray()
                    );

            Console.WriteLine("Certificate created.");
            Console.WriteLine();
            Console.Write("Friendly certificate name:");
            string friendlyName = Console.ReadLine();
            certificate.FriendlyName = friendlyName;
            string pfxPassword = "";
            pfxPassword = GetSecureText(pfxPassword, "Certificate encryption password:");
            if (string.IsNullOrWhiteSpace(pfxPassword))
                pfxPassword = null;

            var certWithPrivKey = certificate.CopyWithPrivateKey(rsa);
            var certBytes = certWithPrivKey.Export(X509ContentType.Pfx, pfxPassword);
            var toExport = new X509Certificate2(certBytes, pfxPassword, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);

            if (saveCert)
                SaveCert(certBytes);

            if (installCert)
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                var existingCerts = store.Certificates.Find(X509FindType.FindByThumbprint, toExport.Thumbprint, false);
                if (existingCerts.Count == 0)
                    store.Add(toExport);
            }

            return certificate;
        }

        private static void SaveCert(byte[] certBytes)
        {
            // TODO if user don't offer output file name, but remove illegal characters from username and use as cert out, or use random text as output file name?
            Console.Write("Output file name:");
            string outputFileName = Console.ReadLine();
            string outputFilePath = $"{outputFileName}.pfx";
            using var fs = File.OpenWrite(outputFilePath);
            fs.Write(certBytes);
            Console.WriteLine($"You may find your certificate at '{Path.GetFullPath(outputFilePath)}'");
        }

        private static Credentials GetCredentials()
        {
            Console.WriteLine();
            string username;
            do
            {
                Console.Write("Enter username:");
                username = Console.ReadLine();
            } while (string.IsNullOrWhiteSpace(username));

            string password = "";
            password = GetSecureText(password, "Enter password:", enforceLength: true);
            return new Credentials { Username = username, Password = password };
        }

        private static string GetSecureText(string password, string message, bool enforceLength = false)
        {
            Console.Write(message);
            bool finished = false;
            do
            {
                var keyInfo = Console.ReadKey(true);
                var keyChar = keyInfo.KeyChar;

                if (keyChar.ToString() == "\r")
                {
                    if (enforceLength && password.Length < 3)
                    {
                        Console.WriteLine("Password is too short. Try again.");
                        Console.Write("Enter password:");
                        password = "";
                        continue;
                    }
                    break;
                }

                password += keyChar;


            } while (!finished || string.IsNullOrWhiteSpace(password));
            Console.WriteLine();
            return password;
        }

        private static void ProcessQuestions(Options o)
        {
            var srcFilePath = o.SourceFilePath;
            string json = File.ReadAllText(srcFilePath);
            JsonSerializerOptions options = QuestionsJsonSerializerOptions();
            var result = JsonSerializer.Deserialize<List<QuizItem>>(json, options);
            Console.WriteLine(JsonSerializer.Serialize(result));
        }

        private static JsonSerializerOptions QuestionsJsonSerializerOptions()
        {
            var options = new JsonSerializerOptions { };
            options.AddDiscriminatorConverterForHierarchy<QuizItem>(QuizItemDiscriminator.DiscriminatorName);
            return options;
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
                Console.WriteLine(input);
            }
        }
    }
}
