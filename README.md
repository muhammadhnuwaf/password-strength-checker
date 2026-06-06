# 🔐 Password Strength Checker

Professional password strength assessment tool built with Python. Compliant with NIST SP 800-63B security guidelines.

---

## 📌 Overview

This tool evaluates password security based on multiple industry standards including length requirements, character diversity, common pattern detection, and entropy calculation.

Password security assessment is critical for:
- Application security testing
- User account protection
- Compliance auditing
- Security awareness training

---

## ✨ Features

- NIST SP 800-63B compliant evaluation
- Password entropy calculation in bits
- Letter grade scoring (A+ to F)
- Common password blacklist (200+ entries)
- Pattern detection (sequential, repeated, keyboard)
- Character diversity analysis
- Hidden password input option
- Export reports to text files
- No external dependencies

---

## 🛠 Technologies Used

- Python 3
- Regular Expressions (re)
- Hash Library (hashlib)
- System Library (getpass)
- Typing Module

---

## 📊 Scoring Criteria

| Score Range | Grade | Strength Level |
|-------------|-------|----------------|
| 90-100 | A+ | EXCELLENT |
| 80-89 | A | VERY STRONG |
| 70-79 | B | STRONG |
| 60-69 | C | MODERATE |
| 45-59 | D | WEAK |
| 25-44 | E | VERY WEAK |
| 0-24 | F | CRITICAL |

---

## 🚀 How to Run

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-checker.git
