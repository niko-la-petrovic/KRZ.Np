using CommandLine;
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
using System.Formats.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Operators;

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

        const string crlDpOid = "2.5.29.31";

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

        #region CLI Options

        private static void ProcessCa(Options o)
        {
            using var rootCaCert = new X509Certificate2(o.SourceFilePath, o.Password,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
            using var cert = GenCert(parentCert: rootCaCert, saveCert: true, isUser: false);
        }

        private static void ProcessRootCa(Options o)
        {
            using var cert = GenCert(parentCert: null, saveCert: true, installCert: true);
        }

        private static void ProcessGame(Options o)
        {
            X509Crl crl;
            X509Certificate2 userCert = null;

            ////var decoder = new AsnReader(rawData, AsnEncodingRules.DER);
            ////var sequence = decoder.ReadSequence();
            ////var nestedSequence = sequence.ReadSequence(Asn1Tag.Sequence);
            ////var contentBytes = nestedSequence.PeekContentBytes().Span;

            var quizItems = LoadQuizItems();

            CaCert registerCaConfig;
            IEnumerable<X509Certificate2> caCerts = cliConfig.CaCerts.Select(cc =>
                new X509Certificate2(
                    cc.FilePath,
                    cc.Password,
                    X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable));
            X509Certificate2 userIssuerCa = null;
            CaCert userIssuerCaConfig = null;

            var db = GetDb();

            bool finished = false;
            bool loginFinished = false;
            User user = null;
            using var sha = SHA256.Create();
            do
            {
                do
                {
                    registerCaConfig = cliConfig.CaCerts[random.Next(cliConfig.CaCerts.Count)];
                    using var regsiterCaCert = new X509Certificate2(registerCaConfig.FilePath, registerCaConfig.Password,
                    X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

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
                        Console.WriteLine("Password is too short");
                        continue;
                    }

                    user = db.Users.FirstOrDefault(dc => dc.Username == creds.Username);
                    if (shouldRegister)
                    {
                        if (user is not null)
                        {
                            Console.WriteLine("Username is already in use");
                            continue;
                        }

                        using var _ = GenCert(parentCert: regsiterCaCert, isUser: true, ski: creds.Username, caCertConfig: registerCaConfig);

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
                        Console.WriteLine("Invalid credentials");
                        continue;
                    }
                    bool validCreds = CheckPassword(sha, creds, user);
                    if (!validCreds)
                    {
                        Console.WriteLine("Invalid credentials");
                        continue;
                    }

                    Console.Write("Specify your digital certificate:");
                    string userCertPath = Console.ReadLine();
                    GetSecureText(out var certPassword, "Enter your certificate password:");
                    Console.WriteLine();
                    try
                    {
                        userCert = new X509Certificate2(userCertPath, certPassword);
                        var issuingCa = caCerts.FirstOrDefault(c => c.Subject == userCert.Issuer);
                        if (issuingCa is null)
                        {
                            Console.WriteLine("The CA issuer of your certificate is invalid");
                            continue;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                        continue;
                    }

                    string crlFilePath = null;
                    try
                    {
                        var certChain = new X509Chain();
                        certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        certChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                        certChain.ChainPolicy.VerificationFlags =
                            X509VerificationFlags.IgnoreEndRevocationUnknown |
                            X509VerificationFlags.IgnoreCtlSignerRevocationUnknown |
                            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                            X509VerificationFlags.IgnoreRootRevocationUnknown |
                            X509VerificationFlags.IgnoreCtlSignerRevocationUnknown;
                        certChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        certChain.ChainPolicy.CustomTrustStore.Add(GetRootCa());
                        foreach (var cert in caCerts)
                        {
                            certChain.ChainPolicy.CustomTrustStore.Add(cert);
                        }
                        certChain.Build(userCert);

                        var chainedUserCert = certChain.ChainElements.Cast<X509ChainElement>().FirstOrDefault();
                        var status = certChain.ChainStatus;
                        if (status.Any())
                        {
                            Console.WriteLine($"Invalid X509 chain: {status.First().StatusInformation}");
                            continue;
                        }

                        var chainElements = certChain.ChainElements.Cast<X509ChainElement>().ToList();
                        var certIssuer = chainElements.Skip(1).FirstOrDefault();
                        var certIssuerThumbprint = certIssuer?.Certificate?.Thumbprint;

                        var ext = userCert.Extensions.Cast<X509Extension>().FirstOrDefault(ext => ext?.Oid.Value == crlDpOid);
                        var rawData = ext.RawData;
                        var crlDistPoint = CrlDistPoint.GetInstance(rawData);
                        var distPoint = crlDistPoint.GetDistributionPoints().FirstOrDefault();
                        var distPointName = distPoint.DistributionPointName.Name;
                        var names = GeneralNames.GetInstance(distPointName).GetNames().FirstOrDefault();
                        var name = names.Name;

                        crlFilePath = name.ToString();

                        userIssuerCa = caCerts.FirstOrDefault(c => c.Subject == userCert.Issuer);
                        if (certIssuerThumbprint is null || certIssuerThumbprint != userIssuerCa?.Thumbprint)
                        {
                            Console.WriteLine("Your CA is not trusted");
                            continue;
                        }
                        userIssuerCaConfig = cliConfig.CaCerts.FirstOrDefault(ca => ca.CrlDPPath == crlFilePath);
                        if (userIssuerCa is null || userIssuerCaConfig is null)
                        {
                            Console.WriteLine("Your certificate CRL DP is not trusted");
                            continue;
                        }

                        crl = GetCrl(userIssuerCa, userIssuerCaConfig.CrlDPPath);
                        var revokedCert = crl.GetRevokedCertificate(new Org.BouncyCastle.Math.BigInteger(userCert.SerialNumber));
                        if (revokedCert is not null)
                        {
                            Console.WriteLine("Your certificate has been revoked");
                            continue;
                        }
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Failed to read CRL DP");
                        continue;
                    }

                    var subjectKey = userCert.Extensions.Cast<X509Extension>().FirstOrDefault(ext => ext?.Oid.Value == X509AuthorityKeyIdentifierExtension.SubjectKeyIdentifierOid.Value) as X509SubjectKeyIdentifierExtension;
                    // TODO make into method, replace other uses
                    var userSki = Convert.ToHexString(Encoding.Default.GetBytes(creds.Username));
                    if (subjectKey.SubjectKeyIdentifier != userSki)
                    {
                        Console.WriteLine("You do not own this certificate");
                        continue;
                    }

                    Console.WriteLine("Successful login");
                    loginFinished = true;


                    int correctAnswers = PlayQuiz(quizItems);
                    int score = (int)(((double)correctAnswers) / toAskCount * 100);
                    var currentDateTime = DateTime.Now;

                    user.PlayCount++;
                    SaveDb(db);

                    if (user.PlayCount == 3)
                    {
                        var modifiedCrl = GetCrl(userIssuerCa, userIssuerCaConfig.CrlDPPath, modify: true, toAdd: userCert);
                        Console.WriteLine("You have played your last game with this certificate");
                    }

                    var gameScores = GetGameScores();

                    Console.WriteLine();
                    Console.WriteLine($"[{currentDateTime}]: Your score is {score}/100");
                    Console.WriteLine();
                    var playScore = new PlayScore { DateTime = currentDateTime, Score = score, Username = user.Username };

                    gameScores.PlayScores.Add(playScore);
                    SaveGameScores(gameScores);

                    Console.Write("Check other users' scores (y/n)?");
                    var checkScore = Console.ReadLine();
                    if (checkScore == "y")
                    {
                        Console.WriteLine($"{Environment.NewLine}Game scores{Environment.NewLine}");
                        Console.WriteLine(gameScores);
                    }

                    Console.WriteLine();
                    Console.Write("Use app again (y/n)?");
                    var useAgain = Console.ReadLine();
                    if (useAgain != "y")
                        finished = true;
                } while (!loginFinished);
            } while (!finished);

            Console.WriteLine();
            Console.WriteLine("Press anything to continue");
            Console.WriteLine();
            Console.ReadKey(true);

            caCerts.ToList().ForEach(c => c?.Dispose());
            userCert?.Dispose();
        }

        private static void ProcessQuestions(Options o)
        {
            var srcFilePath = o.SourceFilePath;
            string json = File.ReadAllText(srcFilePath);
            JsonSerializerOptions options = QuestionsJsonSerializerOptions();
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
                Console.WriteLine(input);
            }
        }

        #endregion

        #region Quiz

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
            Console.WriteLine($"Finished loading {quizItems.Count} quiz items");
            Console.WriteLine();
            return quizItems;
        }

        #endregion

        #region Game Scores

        private static GameScores GetGameScores()
        {
            using var rootCa = GetRootCa();
            var gs = GetGameScores(rootCa, cliConfig.GameScoreConfig.DbPasswordFile, cliConfig.GameScoreConfig.DbFile);
            return gs;
        }

        private static GameScores GetGameScores(X509Certificate2 rootCa, string passwordFilePath, string dataFilePath)
        {
            GameScores gameScores;
            if (!File.Exists(dataFilePath))
            {
                gameScores = new GameScores { PlayScores = new() };
                CryptoWriteJson(gameScores, passwordFilePath, dataFilePath);
            }
            else
            {
                var json = CryptoReadString(rootCa, passwordFilePath, dataFilePath);
                gameScores = JsonSerializer.Deserialize<GameScores>(json);
            }

            return gameScores;
        }

        private static void SaveGameScores(GameScores gameScores)
        {
            CryptoWriteJson(gameScores, cliConfig.GameScoreConfig.DbPasswordFile, cliConfig.GameScoreConfig.DbFile);
        }

        #endregion

        #region Encryption and decryption

        private static void CryptoWriteJson(
            object obj, string passwordFilePath, string dataFilePath)
        {
            string json = JsonSerializer.Serialize(obj);
            CryptoWriteString(json, passwordFilePath, dataFilePath);
        }

        private static void CryptoWriteString(
            string str, string passwordFilePath, string dataFilePath)
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

            using var dfs = File.OpenWrite(dataFilePath);
            var encryptedBytes = AesUtil.EncryptAes(str, aes.Key, aes.IV);
            dfs.Write(encryptedBytes);
        }

        private static string CryptoReadString(X509Certificate2 rootCa, string passwordFilePath, string dataFilePath)
        {
            var pfsBytes = File.ReadAllBytes(passwordFilePath);
            using var rsa = rootCa.GetRSAPrivateKey();
            var decryptedRsa = rsa.Decrypt(pfsBytes, RSAEncryptionPadding.Pkcs1);
            using var reader = new BinaryReader(new MemoryStream(decryptedRsa));
            var iv = reader.ReadBytes(16);
            var keySize = reader.ReadInt32() / 8;
            var key = reader.ReadBytes(keySize);

            var dBytes = File.ReadAllBytes(dataFilePath);
            var readString = AesUtil.DecryptAes(dBytes, key, iv);
            return readString;
        }

        #endregion

        #region Certs

        private static X509Certificate2 GetRootCa(bool exportable = false)
        {
            var storageFlags = X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet;
            if (exportable)
                storageFlags |= X509KeyStorageFlags.Exportable;

            return new X509Certificate2(cliConfig.RootCa.FilePath, cliConfig.RootCa.Password, storageFlags);
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

        private static X509Certificate2 GenCert(
            X509Certificate2 parentCert = null,
            bool saveCert = true,
            bool installCert = true,
            bool isUser = false,
            string ski = null,
            CaCert caCertConfig = null)
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
                var asnEncoder = new AsnWriter(AsnEncodingRules.DER);
                var generalName = new GeneralName(GeneralName.UniformResourceIdentifier, caCertConfig.CrlDPPath);
                var generalNames = new GeneralNames(generalName);
                var dp = new DistributionPoint(new DistributionPointName(generalNames), new ReasonFlags(ReasonFlags.CessationOfOperation), null);
                var crlDistPoint = new CrlDistPoint(new DistributionPoint[] { dp });
                var crlDpDer = crlDistPoint.GetDerEncoded();
                request.CertificateExtensions.Add(new X509Extension(new Oid(crlDpOid), crlDpDer, true));
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

            Console.WriteLine("Certificate created");
            Console.WriteLine();
            Console.Write("Friendly certificate name:");
            string friendlyName = Console.ReadLine();
            certificate.FriendlyName = friendlyName;
            GetSecureText(out var pfxPassword, "Certificate encryption password:");
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

        private static X509Crl GetCrl(X509Certificate2 issuer, string crlDPPath, bool modify = false, X509Certificate2 toAdd = null)
        {
            X509Crl existingCrl = null;
            if (File.Exists(crlDPPath))
            {
                var crlBytes = File.ReadAllBytes(crlDPPath);
                existingCrl = new X509Crl(crlBytes);
            }

            if (!modify && existingCrl is not null)
                return existingCrl;

            var certParser = new X509CertificateParser();
            var bouncyCert = certParser.ReadCertificate((byte[])issuer.RawData);

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(PrincipalUtilities.GetSubjectX509Principal(bouncyCert));
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddDays(10));
            crlGen.SetSignatureAlgorithm(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString().ToUpper());

            if (existingCrl is not null)
            {
                try
                {
                    foreach (X509CrlEntry entry in existingCrl.GetRevokedCertificates())
                        crlGen.AddCrlEntry(entry.SerialNumber, entry.RevocationDate, ReasonFlags.CessationOfOperation);
                }
                catch (NullReferenceException) { }
            }

            if (toAdd is not null)
                crlGen.AddCrlEntry(new Org.BouncyCastle.Math.BigInteger(toAdd.SerialNumber), DateTime.Now, ReasonFlags.CessationOfOperation);

            RsaPrivateCrtKeyParameters privKeyParams;
            {
                // TODO remove. This is to bypass windows limitations of not exporting the private key in plaintext.
                using var loadedRsa = issuer.GetRSAPrivateKey();
                var exported = loadedRsa.ExportEncryptedPkcs8PrivateKey("temp", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1));
                RSA temp = RSA.Create();
                temp.ImportEncryptedPkcs8PrivateKey("temp", exported, out _);
                var loadedPrivate = temp.ExportRSAPrivateKey();

                var privKeyObj = Asn1Object.FromByteArray(loadedPrivate);
                var privKeyStruct = RsaPrivateKeyStructure.GetInstance((Asn1Sequence)privKeyObj);

                privKeyParams = new RsaPrivateCrtKeyParameters(privKeyStruct);
            }

            X509Crl crl = crlGen.Generate(privKeyParams);
            using var fs = File.OpenWrite(crlDPPath);
            fs.Write(crl.GetEncoded());
            return crl;
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

        #endregion

        #region User DB

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
                var json = CryptoReadString(rootCa, passwordFilePath, dataFilePath);
                db = JsonSerializer.Deserialize<Db>(json);
            }

            return db;
        }

        private static void SaveDb(Db db)
        {
            CryptoWriteJson(db, cliConfig.DbConfig.DbPasswordFile, cliConfig.DbConfig.DbFile);
        }

        #endregion

        #region Utility

        private static Credentials GetCredentials()
        {
            Console.WriteLine();
            string username;
            do
            {
                Console.Write("Enter username:");
                username = Console.ReadLine();
            } while (string.IsNullOrWhiteSpace(username));

            GetSecureText(out var password, "Enter password:", enforceLength: true);
            return new Credentials { Username = username, Password = password };
        }

        private static void GetSecureText(out string password, string message, bool enforceLength = false)
        {
            Console.Write(message);
            bool finished = false;
            password = "";
            do
            {
                var keyInfo = Console.ReadKey(true);
                var keyChar = keyInfo.KeyChar;

                if (keyChar.ToString() == "\r")
                {
                    if (enforceLength && password.Length < 3)
                    {
                        Console.WriteLine("Password is too short. Try again");
                        Console.Write("Enter password:");
                        password = "";
                        continue;
                    }
                    break;
                }

                password += keyChar;


            } while (!finished || string.IsNullOrWhiteSpace(password));
            Console.WriteLine();
        }

        private static JsonSerializerOptions QuestionsJsonSerializerOptions()
        {
            var options = new JsonSerializerOptions { };
            options.AddDiscriminatorConverterForHierarchy<QuizItem>(QuizItemDiscriminator.DiscriminatorName);
            return options;
        } 
        #endregion

    }
}
