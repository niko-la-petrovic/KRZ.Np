using System;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;

namespace KRZ.Np.Cryptography
{
    public class Steganography
    {
        private const PixelFormat pixelFormat = PixelFormat.Format24bppRgb;

        /// <summary>
        /// Uses the LSb in each RGB component of a BMP file to hide a byte stream.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="data"></param>
        public static string EncodeBmp(string source, ReadOnlySpan<byte> data)
        {
            using var image = new Bitmap(source);
            EnsurePixelFormat(image);

            var size = image.Size;
            var height = size.Height;
            var width = size.Width;
            EnsureSufficientFileSize(source, data, height, width);

            int dataLength = data.Length;
            var dataLengthBytes = BitConverter.GetBytes(dataLength);

            BitmapData imageData = image.LockBits(
                new Rectangle(0, 0, width, height), ImageLockMode.ReadWrite, pixelFormat);

            byte[] imageBytes = new byte[Math.Abs(imageData.Stride) * height];

            IntPtr scan0 = imageData.Scan0;
            Marshal.Copy(scan0, imageBytes, 0, imageBytes.Length);

            // Write data length as header
            var dataSpan = WriteDataToImageBytes(dataLengthBytes, imageBytes);

            //Write data
            WriteDataToImageBytes(data, dataSpan);

            Marshal.Copy(imageBytes, 0, scan0, imageBytes.Length);
            image.UnlockBits(imageData);

            var parentDir = Directory.GetParent(source);
            var modifiedPath = Path.Join(parentDir.FullName, $"{Path.GetFileNameWithoutExtension(source)}_modified.bmp");
            using var fs = new FileStream(modifiedPath, FileMode.OpenOrCreate);
            image.Save(fs, ImageFormat.Bmp);

            return modifiedPath;
        }

        private static void EnsurePixelFormat(Bitmap image)
        {
            if (image.PixelFormat != pixelFormat)
                throw new InvalidDataException($"Pixel format must be '{pixelFormat}'.");
        }

        private static void EnsureSufficientFileSize(
            string destionationFilePath,
            ReadOnlySpan<byte> data,
            int height,
            int width)
        {
            if (width * height * 3 / 8 < data.Length)
                throw new InvalidDataException($"Destination file '{destionationFilePath}' does not contain enough pixels for {data.Length} bytes.");
        }

        public static string DecodeBmp(string destinationFileName)
        {
            using var image = new Bitmap(destinationFileName);

            EnsurePixelFormat(image);

            var size = image.Size;
            var height = size.Height;
            var width = size.Width;

            BitmapData imageData = image.LockBits(
                new Rectangle(0, 0, width, height), ImageLockMode.ReadWrite, pixelFormat);

            byte[] imageBytes = new byte[Math.Abs(imageData.Stride) * height];

            IntPtr scan0 = imageData.Scan0;
            Marshal.Copy(scan0, imageBytes, 0, imageBytes.Length);

            var readData = ReadDataFromImageBytes(imageBytes);

            int i = BitConverter.ToInt32(readData);
            string decodedData = Encoding.Default.GetString(readData.Slice(sizeof(int), i));

            image.UnlockBits(imageData);

            return decodedData;
        }

        private static Span<byte> ReadDataFromImageBytes(ReadOnlySpan<byte> imageBytes)
        {
            var decodedData = new byte[imageBytes.Length];

            int n = 0;
            for (int i = 0; i < imageBytes.Length / 8; i++)
            {
                byte currentByte = 0;
                for (int j = 0; j < sizeof(byte) * 8; j++)
                {
                    byte imageByte = imageBytes[n];
                    bool bit = (imageByte & 0x1) == 1 ? true : false;
                    if (bit)
                        currentByte = (byte)(currentByte | 1 << j);
                    else
                        currentByte = (byte)(currentByte & ~(1 << j));
                    n++;
                }
                decodedData[i] = currentByte;
            }

            return decodedData;
        }

        private static Span<byte> WriteDataToImageBytes(ReadOnlySpan<byte> data, Span<byte> imageBytes)
        {
            int n = 0;
            for (int i = 0; i < data.Length; i++)
            {
                byte currentByte = data[i];
                for (int j = 0; j < sizeof(byte) * 8; j++)
                {
                    bool bit = ((currentByte >> j) & 0x1) == 1 ? true : false;
                    byte nByte = imageBytes[n];
                    byte newByte;
                    if (bit)
                        newByte = (byte)(nByte | 0x1);
                    else
                        newByte = (byte)(nByte & uint.MaxValue - 1);

                    imageBytes[n] = newByte;
                    n++;
                }
            }

            return imageBytes.Slice(data.Length * 8);
        }

    }
}
