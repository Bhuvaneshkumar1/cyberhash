# ⚡ CyberHash

<p align="center">

```
   ______           __                __  __           __
  / ____/_  _______/ /_  ___  _____  / / / /___ ______/ /_
 / /   / / / / ___/ __ \/ _ \/ ___  / /_/ / __ `/ ___/ __ \
/ /___/ /_/ / /__/ / / /  __/ /    / __  / /_/ (__  ) / / /
\____/\__, /\___/_/ /_/\___/_/    /_/ /_/\__,_/____/_/ /_/
     /____/
```

🔐 **CyberHash — Advanced Hash Analysis & Cracking Tool**

🚀 Built for cybersecurity learning, password security testing, and hash analysis.

</p>

---

# 🧠 Overview

CyberHash is a **Python-based command line hash analysis tool** designed to simulate real-world password cracking techniques used in cybersecurity testing.

The tool supports multiple attack strategies including:

⚡ Dictionary attacks
⚡ Rule-based mutations
⚡ Mask attacks
⚡ Distributed cracking
⚡ Session resume
⚡ Multi-threaded hash analysis

---

# ✨ Features

✅ Automatic hash algorithm detection
✅ Multi-threaded cracking engine
✅ Rule-based mutation engine
✅ Mask attack generator
✅ Session resume & checkpoint system
✅ Distributed cracking support
✅ Benchmark mode for performance testing
✅ Colored CLI interface
✅ Progress monitoring
✅ Custom wordlist support

---

# 🔎 Supported Hash Algorithms

CyberHash detects the algorithm automatically based on hash length.

| Hash Length | Algorithm |
| ----------- | --------- |
| 32          | MD5       |
| 40          | SHA1      |
| 64          | SHA256    |
| 128         | SHA512    |

---

---
> **Note:**
> At present, CyberHash supports a limited number of hash algorithms.
> Future versions of the tool will include support for additional hash types and enhanced cracking capabilities.

---
# 📦 Installation

Clone the repository

```
git clone https://github.com/Bhuvaneshkumar1/cyberhash.git
cd cyberhash
```

Install dependencies

```
pip install -r requirements.txt
```

Install the CLI tool

```
pip install -e .
```

After installation the tool becomes available globally.

```
cyberhash
```

---

# 🚀 Usage

Basic hash analysis

```
cyberhash --hash <hash_value>
```

Example

```
cyberhash --hash 5f4dcc3b5aa765d61d8327deb882cf99
```

---

# ⚙️ Command Line Options

| Option          | Description                  |
| --------------- | ---------------------------- |
| `--hash`        | Target hash value            |
| `--wordlist`    | Custom wordlist path         |
| `--threads`     | Number of worker threads     |
| `--rules`       | Enable rule-based mutations  |
| `--mask`        | Mask attack pattern          |
| `--resume`      | Resume interrupted session   |
| `--distributed` | Distributed cracking workers |
| `--benchmark`   | Run hash speed benchmark     |

---

# 🧨 Attack Modes

## 📚 Dictionary Attack

Uses a wordlist to find the original text.

```
cyberhash --hash <hash>
```

---

## 🧬 Rule Engine Attack

Generates password mutations.

```
cyberhash --hash <hash> --rules
```

Example mutations

```
password
Password
password1
password123
p@ssword
```

---

## 🎭 Mask Attack

Generate passwords from patterns.

Example

```
cyberhash --hash <hash> --mask ?l?l?l?l?d?d
```

Mask symbols

| Symbol | Meaning           |
| ------ | ----------------- |
| `?l`   | lowercase letters |
| `?u`   | uppercase letters |
| `?d`   | digits            |
| `?s`   | symbols           |

---

## ♻️ Resume Attack

Continue interrupted cracking sessions.

```
cyberhash --hash <hash> --resume
```

Session progress is saved automatically.

---

## 🌐 Distributed Cracking

Split workload across multiple processes.

```
cyberhash --hash <hash> --distributed 4
```

---

# 📂 Wordlists

CyberHash supports multiple sources.

1️⃣ Custom user wordlists
2️⃣ Linux system wordlists
3️⃣ Default bundled wordlist

Default location

```
wordlists/default_wordlist.txt
```

For stronger cracking performance use larger lists such as:

* SecLists
* rockyou.txt

---

# 📊 Example

```
cyberhash --hash 5f4dcc3b5aa765d61d8327deb882cf99 --rules --threads 8
```

---

# 📁 Project Structure

```
cyberhash/
│
├── cyberhash.py
├── setup.py
├── requirements.txt
├── README.md
│
├── wordlists/
│   └── default_wordlist.txt
│
└── logs/
```

---

# ⚠️ Disclaimer

This project is intended **for educational purposes and authorized security testing only**.

Do not use this tool against systems without permission.

---

# 👨‍💻 Author

**Bhuvanesh Kumar**
Cybersecurity Enthusiast

GitHub
https://github.com/Bhuvaneshkumar1

---

⭐ If you find this project useful, consider giving it a star on GitHub.
