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
using eBay.ApiClient.Auth.OAuth2;
using eBay.ApiClient.Auth.OAuth2.Model;
using System.Security.AccessControl;

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
        private OAuth2Api AuthAPI = new OAuth2Api();
        private IList<String> scopes = new List<String>();
        private OAuthEnvironment environment = OAuthEnvironment.SANDBOX;
        private OAuthResponse appToken = null;
        private String AuthURL = null;


        public LoginPage()
        {
            this.InitializeComponent();
            this.ProtectData();
            try
            {
                string configName = "ebay-config.yaml";
                System.Diagnostics.Debug.WriteLine("Adding access control entry for " + configName);

                CredentialUtil.Load("C:\\Users\\15049\\Documents\\GitHub\\eBayZoom\\eBayZoom\\ebay-config.yaml");
                System.Diagnostics.Debug.WriteLine("Config successfully loaded.");
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine("Error, program settings unable to be read. Thrown: " + e.Message);
            }
            FillScopes();
            //appToken = AuthAPI.GetApplicationToken(environment, scopes);
            //AuthURL = AuthAPI.GenerateUserAuthorizationUrl(environment, scopes, appToken.AccessToken.Token);
        }

        private void FillScopes()
        {
            scopes.Add("https://api.ebay.com/oauth/api_scope");
            scopes.Add("https://api.ebay.com/oauth/api_scope/buy.order.readonly");
            scopes.Add("https://api.ebay.com/oauth/api_scope/sell.inventory");
            scopes.Add("https://api.ebay.com/oauth/api_scope/sell.account");
            scopes.Add("https://api.ebay.com/oauth/api_scope/sell.fulfillment");
            scopes.Add("https://api.ebay.com/oauth/api_scope/commerce.identity.readonly");
            scopes.Add("https://api.ebay.com/oauth/api_scope/commerce.identity.email.readonly");
            scopes.Add("https://api.ebay.com/oauth/api_scope/commerce.identity.address.readonly");
            scopes.Add("https://api.ebay.com/oauth/api_scope/commerce.identity.name.readonly");
            scopes.Add("https://api.ebay.com/oauth/api_scope/sell.finances");
            scopes.Add("https://api.ebay.com/oauth/api_scope/sell.item");
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
                        if(text.Length != 0 && text.IndexOf(" ") > 0 )
                        {
                            Username.Text = text.Substring(0, text.IndexOf(" "));
                            Password.Password = text.Substring(text.IndexOf(" ") + 1);
                            saveLogin = true;
                            SavePasswordCheckBox.IsChecked = true;
                        }
                        
                    }
                }
            }
        }

        public static void AddFileSecurity(string fileName, string account,
            FileSystemRights rights, AccessControlType controlType)
        {

            // Get a FileSecurity object that represents the
            // current security settings.
            FileSecurity fSecurity = File.GetAccessControl(fileName);

            // Add the FileSystemAccessRule to the security settings.
            fSecurity.AddAccessRule(new FileSystemAccessRule(account,
                rights, controlType));

            // Set the new access settings.
            File.SetAccessControl(fileName, fSecurity);
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
            else
            {
                configSF = await storageFolder.CreateFileAsync("config.txt", Windows.Storage.CreationCollisionOption.ReplaceExisting);
            }
        }
    }

    
    }
