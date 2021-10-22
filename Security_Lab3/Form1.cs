using System;
using System.Text;
using System.IO;
using System.Windows.Forms;

namespace Security_Lab3
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            var c = MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes("aa"), "password");
            string s = Convert.ToBase64String(c);
            
            var p = MyRC5.DecryptCBCPad(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);
        }

        private void label2_Click(object sender, EventArgs e)
        {

        }

        private void button3_Click(object sender, EventArgs e)
        {
            textBox_output.Text = Convert.ToBase64String
                (MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes(textBox_message.Text), textBox_key.Text));
        }

        private void button4_Click(object sender, EventArgs e)
        {
            textBox_output.Text = Encoding.ASCII.GetString(
                MyRC5.DecryptCBCPad(Convert.FromBase64String(textBox_message.Text), textBox_key.Text));
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
                textBox_message.Text = File.ReadAllText(openFileDialog1.FileName);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (saveFileDialog1.ShowDialog() == DialogResult.OK)
                File.WriteAllText(saveFileDialog1.FileName, textBox_output.Text);
        }
    }
}
