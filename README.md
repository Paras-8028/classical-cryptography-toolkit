# 🔐 Classical Cryptography Toolkit

### An Interactive Web-Based Application for Classical Encryption and Decryption

<p align="center">
  <strong>A Network Security Mini Project</strong><br>
  Final Year Electronics and Computer Engineering | 2026–2027
</p>

<p align="center">
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5">
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white" alt="CSS3">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Network-Security-0A66C2?style=for-the-badge" alt="Network Security">
</p>

---

## 📌 Project Overview

The **Classical Cryptography Toolkit** is a web-based educational application designed to demonstrate the working principles of classical encryption and decryption algorithms.

The application provides an interactive interface where users can select a cipher, enter plaintext and the required key, encrypt messages, decrypt ciphertext, and explore the differences between various classical cryptographic techniques.

Developed using **HTML, CSS, and JavaScript**, the application runs directly in a modern web browser without requiring a backend server or database.

The project aims to make classical cryptography easier to understand through practical implementation, interactive demonstrations, and algorithm comparisons.

---

## 🎯 Objectives

- Understand the fundamental concepts of cryptography, encryption, and decryption.
- Implement classical substitution and transposition ciphers.
- Develop a user-friendly interface for performing encryption and decryption.
- Demonstrate the importance of cryptographic keys and key validation.
- Compare different classical encryption algorithms.
- Explore text-file encryption and decryption using browser-based functionality.
- Understand the limitations of classical cryptographic algorithms in modern cybersecurity.

---

## ❓ Problem Statement

Classical cryptography introduces important concepts in information security, but understanding encryption algorithms can be challenging without practical demonstrations.

The objective of this project is to develop a menu-driven, browser-based cryptography toolkit that implements multiple classical encryption algorithms and provides an interactive environment for experimenting with plaintext, ciphertext, and cryptographic keys.

The application should allow users to encrypt and decrypt messages, compare algorithms, process text files, and understand the strengths and limitations of classical ciphers.

---

## ✨ Features

### 🔒 Multiple Encryption Algorithms

Implements eight classical encryption algorithms covering substitution and transposition techniques.

### 🔓 Encryption and Decryption

Allows users to encrypt plaintext and decrypt ciphertext using the appropriate algorithm and key.

### 🗝️ Key Management

Supports different key formats, including numeric shifts, substitution alphabets, keywords, matrix keys, and random alphabetic keys.

### 📊 Algorithm Comparison

Provides a comparison of classical ciphers based on their working principles, key types, advantages, limitations, and educational security considerations.

### 📁 Text File Processing

Supports loading text files, processing their contents, and downloading encrypted or decrypted results when file functionality is implemented.

### ⚡ Execution Time Measurement

Can display approximate browser-side execution time for encryption and decryption operations.

### 📋 Copy Results

Provides convenient copying of ciphertext, decrypted text, and generated keys when clipboard functionality is implemented.

### 🛡️ Input Validation

Validates user inputs and cryptographic keys to help prevent invalid operations.

### 🎨 Modern User Interface

Features a responsive interface designed for convenient use on desktop, tablet, and mobile devices.

### 📚 Help and Documentation

Explains cryptographic concepts, algorithm operations, key requirements, and usage instructions.

> **Implementation note:** The feature list describes the intended project scope. Ensure each feature is implemented and tested in your application before presenting it as completed.

---

## 🔐 Implemented Cryptographic Algorithms

The toolkit covers eight classical encryption algorithms.

### 1. Caesar Cipher

A substitution cipher that shifts each alphabetic character by a fixed number of positions.

**Encryption formula:**

\[
E(x) = (x + k) \bmod 26
\]

**Decryption formula:**

\[
D(x) = (x - k + 26) \bmod 26
\]

Where:
- \(x\) represents the numerical position of a letter.
- \(k\) represents the shift key.

**Example:**

| Parameter | Value |
|---|---|
| Plaintext | NETWORK SECURITY |
| Key | 5 |
| Ciphertext | SJYBTWP XJHZWNYD |

**Key type:** Integer

### 2. Monoalphabetic Substitution Cipher

A substitution cipher in which each letter of the plaintext alphabet maps to a corresponding letter in a substitution alphabet.

**Features:**
- Uses a 26-letter substitution key.
- Requires every alphabet letter to appear exactly once in the key.
- Uses the inverse mapping for decryption.
- Can support random substitution-key generation.

**Key type:** Permutation of the English alphabet

### 3. Playfair Cipher

A digraph substitution cipher that encrypts pairs of letters using a 5 × 5 key matrix.

**Working principle:**
1. Generate a matrix from a keyword.
2. Combine I and J into one cell.
3. Divide normalized plaintext into pairs.
4. Insert filler characters where required.
5. Encrypt each pair using the Playfair rules.

**Key type:** Keyword

**Important:** Decryption may require removing filler characters inserted during encryption.

### 4. Hill Cipher

A polygraphic substitution cipher that uses matrix multiplication and modular arithmetic.

**Encryption formula:**

\[
C = KP \bmod 26
\]

**Decryption formula:**

\[
P = K^{-1}C \bmod 26
\]

Where:
- \(P\) is the plaintext vector.
- \(C\) is the ciphertext vector.
- \(K\) is the key matrix.
- \(K^{-1}\) is the modular inverse of the key matrix.

The implementation uses a 2 × 2 key matrix.

**Key type:** Invertible matrix modulo 26

**Important:** The matrix must have a determinant relatively prime to 26 to be invertible modulo 26.

### 5. Vigenère Cipher

A polyalphabetic substitution cipher that uses a repeating keyword to encrypt alphabetic characters.

**Encryption formula:**

\[
C_i = (P_i + K_i) \bmod 26
\]

**Decryption formula:**

\[
P_i = (C_i - K_i + 26) \bmod 26
\]

**Features:**
- Uses a keyword instead of a single shift value.
- Applies different shifts according to the key.
- Can preserve spaces and punctuation without advancing the key position over them.

**Key type:** Alphabetic keyword

### 6. One-Time Pad

An encryption technique that combines plaintext with a key of equal length.

**Encryption formula:**

\[
C_i = (P_i + K_i) \bmod 26
\]

**Decryption formula:**

\[
P_i = (C_i - K_i + 26) \bmod 26
\]

**Requirements for a true One-Time Pad:**
- The key must be uniformly random.
- The key must be as long as the message.
- The key must remain secret.
- The key must never be reused.

**Key type:** Random alphabetic key

A browser-based demonstration does not automatically guarantee the security properties of a true One-Time Pad.

### 7. Rail Fence Cipher

A transposition cipher that arranges plaintext characters in a zigzag pattern across multiple rails.

The ciphertext is produced by reading the characters rail by rail.

**Example input:**

`WEAREDISCOVEREDFLEEATONCE`

**Number of rails:** 3

**Expected ciphertext:**

`WECRLTEERDSOEEFEAOCAIVDEN`

**Key type:** Number of rails

### 8. Columnar Transposition Cipher

A transposition cipher that arranges plaintext in rows and reads the columns according to the alphabetical ordering of a keyword.

**Working principle:**
1. Select a keyword.
2. Write the plaintext into a grid row by row.
3. Determine the column order using the keyword.
4. Read the columns in the selected order.
5. Apply the corresponding reverse process during decryption.

**Key type:** Alphabetic keyword

The implementation should define how repeated keyword letters and padding are handled.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| HTML5 | Structure of the web application |
| CSS3 | Styling, layout, animations, and responsiveness |
| JavaScript | Encryption algorithms, decryption, validation, and application logic |
| Browser APIs | Clipboard access and local text-file processing |
| Git | Version control |
| GitHub | Source-code hosting and project collaboration |

### Software Requirements

- A modern web browser such as Google Chrome, Microsoft Edge, or Mozilla Firefox.
- A code editor such as Visual Studio Code.
- Git, if you want to manage the project using version control.
- An internet connection for accessing the GitHub repository; internet access is not required for the core application if it uses only local resources.

No backend server, database, package manager, or build process is required for the basic frontend implementation.

---

## 📂 Project Structure

The project uses three primary files:

```text
NS Mini Project/
│
├── index.html      # Application structure and interface
├── styles.css      # Styling and responsive layout
├── script.js       # Encryption algorithms and application logic
└── README.md       # Project documentation
```

Additional files may be added later for screenshots, documentation, or other project deliverables.

---

## 🚀 Getting Started

### Prerequisites

Install or use:
- A modern web browser.
- A code editor, if you want to inspect or modify the source code.

### Installation

**Step 1: Clone the repository**

```bash
git clone https://github.com/Paras-8028/classical-cryptography-toolkit.git
```

**Step 2: Navigate to the project directory**

```bash
cd classical-cryptography-toolkit
```

**Step 3: Open the application**

Open `index.html` directly in your browser.

Alternatively, open the project in Visual Studio Code and use the Live Server extension.

No additional installation or build commands are required for the basic frontend application.

---

## 💻 How to Use

### Encrypting Text

1. Open the application in your browser.
2. Select the desired encryption algorithm.
3. Enter the plaintext.
4. Enter the required key or generate one if the selected algorithm supports key generation.
5. Click the **Encrypt** button.
6. Review the generated ciphertext.
7. Copy the ciphertext or download it if the relevant feature is available.

### Decrypting Text

1. Select the algorithm used to encrypt the message.
2. Enter the ciphertext.
3. Provide the correct key.
4. Click the **Decrypt** button.
5. Review the decrypted result.

### Comparing Algorithms

1. Open the Algorithm Comparison section.
2. Select the algorithms you want to compare.
3. Provide the required keys.
4. Enter the test plaintext.
5. Review the ciphertext generated by each selected algorithm.

### Processing Text Files

1. Open the File Encryption or File Decryption section.
2. Select a text file from your device.
3. Choose the appropriate cipher.
4. Enter the required key.
5. Perform encryption or decryption.
6. Download the resulting text file if supported.

---

## 🧪 Sample Inputs and Outputs

### Test Case 1: Caesar Cipher

**Input**

```text
Plaintext: NETWORK SECURITY
Key: 5
```

**Expected output**

```text
Encrypted Text: SJYBTWP XJHZWNYD
Decrypted Text: NETWORK SECURITY
```

### Test Case 2: Caesar Cipher with Mixed Case

**Input**

```text
Plaintext: Hello World!
Key: 3
```

**Expected output**

```text
Encrypted Text: Khoor Zruog!
Decrypted Text: Hello World!
```

### Test Case 3: Vigenère Cipher

**Input**

```text
Plaintext: ATTACKATDAWN
Key: LEMON
```

**Expected output**

```text
Encrypted Text: LXFOPVEFRNHR
Decrypted Text: ATTACKATDAWN
```

### Test Case 4: Hill Cipher

**Input**

```text
Plaintext: HELP

Key Matrix:
3 3
2 5
```

**Expected output**

```text
Encrypted Text: HIAT
Decrypted Text: HELP
```

The matrix must be applied consistently using the same vector convention for encryption and decryption.

### Test Case 5: Rail Fence Cipher

**Input**

```text
Plaintext: WEAREDISCOVEREDFLEEATONCE
Rails: 3
```

**Expected output**

```text
Encrypted Text: WECRLTEERDSOEEFEAOCAIVDEN
Decrypted Text: WEAREDISCOVEREDFLEEATONCE
```

### Test Case 6: Monoalphabetic Cipher

**Input:**
- A valid 26-letter substitution alphabet.
- A plaintext message.

**Expected result:**
- The application produces ciphertext using the selected substitution alphabet.
- Decryption using the same key recovers the original message.

### Test Case 7: Playfair Cipher

**Input:**
- A keyword.
- An alphabetic plaintext message.

**Expected result:**
- The application generates a 5 × 5 key matrix.
- Encryption operates on digraphs.
- Decryption recovers the normalized plaintext, subject to documented filler-character handling.

### Test Case 8: One-Time Pad

**Input:**
- A normalized plaintext.
- A random key of equal alphabetic length.

**Expected result:**
- Encryption produces ciphertext.
- Decryption using the same key recovers the normalized plaintext.

### Test Case 9: Columnar Transposition

**Input:**
- A plaintext message.
- A keyword.

**Expected result:**
- Encryption rearranges the characters according to the column order.
- Decryption reconstructs the original message according to the implementation's padding convention.

> **Note:** These are expected results for verification. Confirm each result against your actual implementation before claiming that the corresponding test has passed.

---

## 🧰 Testing

The application should be tested for the following scenarios.

| Test ID | Test Scenario | Expected Result |
|---|---|---|
| TC-01 | Caesar encryption with a valid key | Correct ciphertext is generated |
| TC-02 | Caesar decryption | Original text is recovered |
| TC-03 | Vigenère encryption and decryption | Correct round trip |
| TC-04 | Monoalphabetic cipher with a valid key | Encryption and decryption succeed |
| TC-05 | Monoalphabetic key with duplicate letters | Invalid key is rejected |
| TC-06 | Playfair encryption and decryption | Normalized plaintext is recovered |
| TC-07 | Hill cipher with an invertible matrix | Encryption and decryption succeed |
| TC-08 | Hill cipher with a non-invertible matrix | An informative error is displayed |
| TC-09 | One-Time Pad with an incorrect key length | Invalid key is rejected |
| TC-10 | Rail Fence with a valid rail count | Encryption and decryption succeed |
| TC-11 | Columnar Transposition with repeated keyword letters | Consistent column ordering is applied |
| TC-12 | Empty plaintext or missing key | Appropriate validation message appears |
| TC-13 | Text-file upload and download | File processing works as intended |
| TC-14 | Copying ciphertext | Text is copied when clipboard access is available |
| TC-15 | Mobile and tablet layouts | Interface remains usable |
| TC-16 | Navigation between application sections | Correct section is displayed |

Testing should include normal inputs, invalid keys, empty inputs, punctuation, mixed-case text, and short messages.

---

## 🔍 Advantages

- Provides an interactive way to learn classical cryptography.
- Combines eight algorithms in a single application.
- Demonstrates both substitution and transposition techniques.
- Helps students understand encryption and decryption.
- Supports experimentation with different keys.
- Runs in a web browser without requiring a backend.
- Can process text locally without sending it to an external server.
- Provides a foundation for studying modern cryptographic techniques.

---

## ⚠️ Limitations and Security Considerations

This project is intended for educational purposes.

- Caesar Cipher can be broken by trying a small number of possible shifts.
- Monoalphabetic substitution is vulnerable to frequency analysis.
- Playfair Cipher has weaknesses against statistical cryptanalysis.
- Hill Cipher is vulnerable to known-plaintext attacks and other cryptanalytic techniques.
- Vigenère Cipher can be attacked using key-length analysis and frequency analysis.
- Rail Fence and Columnar Transposition do not provide modern cryptographic security.
- A One-Time Pad is secure only when its strict key-generation and key-management requirements are satisfied.
- Browser-based classical cipher implementations should not be used to protect confidential files or sensitive communications.
- Padding and text normalization can affect whether decryption reconstructs the exact original input.
- Client-side processing does not by itself guarantee complete privacy if the application is modified to include external scripts or data transmission.

For real-world applications, use established, authenticated encryption methods and well-maintained cryptographic libraries rather than classical ciphers.

---

## 🔮 Future Scope

The project can be extended with the following features:

- Graphical interface improvements and interactive cipher visualizations.
- Additional classical algorithms, such as Affine Cipher and Autokey Cipher.
- Modern cryptographic demonstrations, such as AES and RSA.
- Secure key generation and key-management demonstrations.
- More comprehensive file-handling functionality.
- Downloadable encryption and decryption reports.
- Algorithm performance comparison across different input sizes.
- Improved accessibility and multilingual support.
- Automated unit tests for all cipher implementations.
- Educational exercises and quizzes about cryptography.
- A guided learning mode explaining each encryption step.
- Optional backend integration for features that genuinely require server-side processing.

Any implementation of modern cryptography should use established cryptographic libraries rather than custom cryptographic primitives.

---

## 🎓 Academic Information

| Field | Details |
|---|---|
| Project Title | Design and Development of a Classical Cryptography Toolkit |
| Subject | Network Security |
| Project Type | Mini Project |
| Academic Year | 2026–2027 |
| Class | Final Year (ECM) |
| Department | Electronics and Computer Engineering |
| Frontend Technologies | HTML, CSS, JavaScript |

### Student Details

- **Name:** Maharudra Patil
- **Roll Number:** [Enter your roll number]
- **Batch:** [Enter your batch]

### Institution

**Walchand Institute of Technology, Solapur**

---

## 📚 Learning Outcomes

Through this project, students can gain practical experience in:

- Understanding fundamental cryptographic terminology.
- Implementing substitution and transposition algorithms.
- Applying modular arithmetic and matrix operations.
- Designing reusable JavaScript functions.
- Validating user input and handling errors.
- Building interactive web applications.
- Testing encryption and decryption operations.
- Understanding why historical cryptographic algorithms are not suitable for modern security.

---

## 🔗 Project Links

- **GitHub Repository:** https://github.com/Paras-8028/classical-cryptography-toolkit
- **Live Demo:** [Add your deployed application URL here, if available]
- **Project Report:** [Add the report link here, if available]
- **Demonstration Video:** [Add the video link here, if available]

---

## 📄 License

This project is intended for educational and academic use.

If you plan to publish or redistribute the source code, consider adding an appropriate open-source license, such as the MIT License, after deciding the terms under which others may use the project.

---

## 🙌 Acknowledgements

This project was developed as part of the Network Security mini-project curriculum to explore classical cryptography and its role in the historical development of information security.

The project demonstrates the implementation of traditional encryption and decryption techniques through a browser-based application.

---

<p align="center">
  <strong>Classical Cryptography Toolkit</strong><br>
  Learn Cryptography. Understand Encryption. Explore Network Security.
</p>