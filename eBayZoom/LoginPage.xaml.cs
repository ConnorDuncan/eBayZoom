using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography.DataProtection;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using System.Threading.Tasks;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace eBayZoom
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class LoginPage : Page
    {
        private Windows.Storage.StorageFile configSF;
        private Windows.Storage.StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
        private bool saveLogin = false;
        private BinaryStringEncoding encoding = BinaryStringEncoding.Utf16BE;
        private String strDescriptor = "LOCAL=user";


        public LoginPage()
        {
            this.InitializeComponent();
            this.ProtectData();
        }

        private async void ProtectData()
        {
            if(await storageFolder.TryGetItemAsync("config.txt") != null) // if user file exists
            {
                configSF = await storageFolder.GetFileAsync("config.txt");
                var stream = await configSF.OpenAsync(Windows.Storage.FileAccessMode.Read);
                ulong size = stream.Size;
                using (var inputStream = stream.GetInputStreamAt(0))
                {
                    using (var dataReader = new Windows.Storage.Streams.DataReader(inputStream))
                    {
                        uint numBytesLoaded = await dataReader.LoadAsync((uint)size);
                        IBuffer textBuffer = dataReader.ReadBuffer(numBytesLoaded);
                        string text = await SampleDataUnprotectStream(textBuffer, encoding);
                        Username.Text = text.Substring(0, text.IndexOf(" "));
                        Password.Password = text.Substring(text.IndexOf(" ") + 1);
                        // Call helper method, query ebay api
                    }
                }
            }
        }

        private async Task<IBuffer> SampleDataProtectionStream(
            String descriptor,
            String strMsg,
            BinaryStringEncoding encoding)
        {
            // Create a DataProtectionProvider object for the specified descriptor.
            DataProtectionProvider Provider = new DataProtectionProvider(descriptor);

            // Convert the input string to a buffer.
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(strMsg, encoding);

            // Create a random access stream to contain the plaintext message.
            InMemoryRandomAccessStream inputData = new InMemoryRandomAccessStream();

            // Create a random access stream to contain the encrypted message.
            InMemoryRandomAccessStream protectedData = new InMemoryRandomAccessStream();

            // Retrieve an IOutputStream object and fill it with the input (plaintext) data.
            IOutputStream outputStream = inputData.GetOutputStreamAt(0);
            DataWriter writer = new DataWriter(outputStream);
            writer.WriteBuffer(buffMsg);
            await writer.StoreAsync();
            await outputStream.FlushAsync();

            // Retrieve an IInputStream object from which you can read the input data.
            IInputStream source = inputData.GetInputStreamAt(0);

            // Retrieve an IOutputStream object and fill it with encrypted data.
            IOutputStream dest = protectedData.GetOutputStreamAt(0);
            await Provider.ProtectStreamAsync(source, dest);
            await dest.FlushAsync();

            //Verify that the protected data does not match the original
            DataReader reader1 = new DataReader(inputData.GetInputStreamAt(0));
            DataReader reader2 = new DataReader(protectedData.GetInputStreamAt(0));
            await reader1.LoadAsync((uint)inputData.Size);
            await reader2.LoadAsync((uint)protectedData.Size);
            IBuffer buffOriginalData = reader1.ReadBuffer((uint)inputData.Size);
            IBuffer buffProtectedData = reader2.ReadBuffer((uint)protectedData.Size);

            if (CryptographicBuffer.Compare(buffOriginalData, buffProtectedData))
            {
                throw new Exception("ProtectStreamAsync returned unprotected data");
            }

            // Return the encrypted data.
            return buffProtectedData;
        }

        private async Task<String> SampleDataUnprotectStream(
            IBuffer buffProtected,
            BinaryStringEncoding encoding)
        {
            // Create a DataProtectionProvider object.
            DataProtectionProvider Provider = new DataProtectionProvider();

            // Create a random access stream to contain the encrypted message.
            InMemoryRandomAccessStream inputData = new InMemoryRandomAccessStream();

            // Create a random access stream to contain the decrypted data.
            InMemoryRandomAccessStream unprotectedData = new InMemoryRandomAccessStream();

            // Retrieve an IOutputStream object and fill it with the input (encrypted) data.
            IOutputStream outputStream = inputData.GetOutputStreamAt(0);
            DataWriter writer = new DataWriter(outputStream);
            writer.WriteBuffer(buffProtected);
            await writer.StoreAsync();
            await outputStream.FlushAsync();

            // Retrieve an IInputStream object from which you can read the input (encrypted) data.
            IInputStream source = inputData.GetInputStreamAt(0);

            // Retrieve an IOutputStream object and fill it with decrypted data.
            IOutputStream dest = unprotectedData.GetOutputStreamAt(0);
            await Provider.UnprotectStreamAsync(source, dest);
            await dest.FlushAsync();

            // Write the decrypted data to an IBuffer object.
            DataReader reader2 = new DataReader(unprotectedData.GetInputStreamAt(0));
            await reader2.LoadAsync((uint)unprotectedData.Size);
            IBuffer buffUnprotectedData = reader2.ReadBuffer((uint)unprotectedData.Size);

            // Convert the IBuffer object to a string using the same encoding that was
            // used previously to conver the plaintext string (before encryption) to an
            // IBuffer object.
            String strUnprotected = CryptographicBuffer.ConvertBinaryToString(encoding, buffUnprotectedData);

            // Return the decrypted data.
            return strUnprotected;
        }
        private void SaveLogin_Toggle(object sender, RoutedEventArgs e)
        {
            saveLogin = !saveLogin;
        }

        private void Pass_Change(object sender, TextChangedEventArgs e)
        {
            
        }

        private void User_Change(object sender, TextChangedEventArgs e)
        {
            
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            if (saveLogin)
            {
                configSF = await storageFolder.CreateFileAsync("config.txt", Windows.Storage.CreationCollisionOption.ReplaceExisting);
                var stream = await configSF.OpenAsync(Windows.Storage.FileAccessMode.ReadWrite);
                using (var outputStream = stream.GetOutputStreamAt(0))
                {
                    using (var dataWriter = new Windows.Storage.Streams.DataWriter(outputStream))
                    {
                        string combo = Username.Text + " " + Password.Password;
                        IBuffer comboB = await SampleDataProtectionStream(strDescriptor, combo, encoding);
                        dataWriter.WriteBuffer(comboB);
                        await dataWriter.StoreAsync();
                        await outputStream.FlushAsync();
                    }
                }
                stream.Dispose();
            }
        }
    }

    
    }
