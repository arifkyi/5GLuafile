# NR 5GS Full Decoder for Wireshark

**A LUA script that enables complete NR 5GS (5G New Radio Service) message decoding in Wireshark**

## 📋 Overview

This LUA script enhances Wireshark's capabilities by providing full decoding support for NR 5GS protocol messages, making it easier to analyze and troubleshoot 5G network communications.

## 🚀 Features

- Complete NR 5GS message decoding
- Easy integration with Wireshark
- Enhanced protocol analysis for 5G networks
- User-friendly implementation

## 📺 Installation Guide

For a comprehensive step-by-step installation tutorial, please watch our video guide:

**[📹 Watch Installation Tutorial on YouTube](https://www.youtube.com/watch?v=b0dbvIkkgCI)**

## 🛠️ Quick Setup

1. Download the LUA script from this repository
2. Copy the script to your Wireshark plugins directory
3. Restart Wireshark
4. Enable the decoder in your protocol preferences

*Detailed instructions are available in the video tutorial linked above*

## 📱 Requirements

- Wireshark (version X.X or higher)
- Basic understanding of 5G NR protocols
- Administrative access to install plugins

## 💡 Usage

Once installed, the decoder will automatically parse NR 5GS messages in your packet captures. Simply:
1. Open your 5G packet capture file
2. Apply relevant display filters
3. View decoded NR 5GS messages in the packet details pane

## 🔧 Troubleshooting

### LTE/4G Traffic Not Decoding?

If your PCAP contains LTE traffic that's not being decoded properly:

1. Go to **Analyze** → **Decode As...**
2. Find **UDP port 4729** in the list
3. In the **"Current"** column, change from **GSMTAPv3** to **GSMTAP**
4. Click **OK** to apply changes

This allows you to switch between GSMTAPv3 (for 5G) and GSMTAP (for 4G/LTE) decoding as needed.

## ☕ Support Me, Support Rifky The Cyber YouTube Channel

If you find this tool helpful and would like to support its development, you can buy me a coffee!

**[☕ Support on Ko-fi](https://ko-fi.com/rifkythecyber)**

Or scan the QR code below:

<img src="https://github.com/user-attachments/assets/a6529b25-06eb-4072-9077-6682aad0807a" alt="Donate" width="200">

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Summary:** You can use, modify, and distribute this code freely, just keep the original copyright notice.

## 🙏 Acknowledgments

- Thanks to all contributors and users
- Special thanks to the Wireshark community

---

**⭐ If you find this project useful, please consider giving it a star!**