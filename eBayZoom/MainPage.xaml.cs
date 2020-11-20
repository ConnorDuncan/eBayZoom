using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace eBayZoom
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private Windows.Storage.StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
        public MainPage()
        {
            this.InitializeComponent();
            InnerFrame.Navigate(typeof(LoginPage));
            
        }

        private async void InnerFrame_Navigated(object sender, NavigationEventArgs e)
        {
            if (await storageFolder.TryGetItemAsync("config.txt") != null)
            {
                // Login with settings, navigate to different page
            }
            else { 
                // Do nothing? 
            }
        }
    }
}
