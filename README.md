# 🕵️‍♂️ SQLi_enum – Blind SQL Injection Enumerator for CTFs

`SQLi_enum.py` is a command-line tool for blind SQL injection exploitation in CTFs or lab environments.  
It automates the process of extracting:

- ✅ Database names  
- ✅ Table names  
- ✅ Column names  
- ✅ Column values (e.g., usernames)  
- ✅ Passwords for selected users

All without assuming any schema details.

---

## ⚠️ Disclaimer

> **For educational use only.**  
> Do not use this tool on systems you do not own or have explicit permission to test.  
> The author takes no responsibility for misuse.

---

## 🛠 Features

- 🔢 Specify exact number of UNION SELECT columns with `--columns`
- 📄 Customizable success string (e.g. `"Welcome"`)
- 🔍 Enumerates schema dynamically
- 🔐 Extracts usernames, then passwords
- ✅ No assumptions about column names or structure
- 🔤 Expanded charset for realistic password extraction
- ✨ Live progress during character-by-character extraction

---

## 🚀 Usage

```bash
python3 SQLi_enum.py --success "Welcome" --columns 4 http://target.url
```

---

## 📖 Arguments
Argument	Description
- url	The target URL (must be POST-based login page)
- --success	Success string that appears in a successful login response
- --columns	Number of columns required for UNION SELECT

---

## 🔧 Requirements
- Python 3.x
- requests library

Install via:
- pip install requests

---

## 💡 Tips
- Use Burp Suite or browser dev tools to inspect how the login form submits data.
- Adjust the success string if the target app uses different responses.
- Ensure the column count (--columns) matches what the database expects.

