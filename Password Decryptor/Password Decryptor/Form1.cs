using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Password_Decryptor
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string val = "CTsvjZ0jQghXYWbSRcPxpQ==";
            string key = "J8gLXc454o5tW2HEF7HahcXPufj9v8k8";
            string iv = "fq20T0gMnXa6g0l4";

            byte[] inputBuffer = Convert.FromBase64String(val);
            AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider();
            cryptoServiceProvider.BlockSize = 128;
            cryptoServiceProvider.KeySize = 256;
            cryptoServiceProvider.Key = Encoding.ASCII.GetBytes(key);
            cryptoServiceProvider.IV = Encoding.ASCII.GetBytes(iv);
            cryptoServiceProvider.Padding = PaddingMode.PKCS7;
            cryptoServiceProvider.Mode = CipherMode.CBC;
            string decryptedDBPassword = Encoding.ASCII.GetString(cryptoServiceProvider.CreateDecryptor(cryptoServiceProvider.Key, cryptoServiceProvider.IV).TransformFinalBlock(inputBuffer, 0, inputBuffer.Length));
            label1.Text = decryptedDBPassword;
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }
    }
}
