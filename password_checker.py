"""
PROJECT: Password Strength Checker
AUTHOR: Muhammadh Nuwaf
COURSE: Pearson BTEC HND in Computing (Cyber Security)
MODULE: Information Security Management
DATE: June 2026
VERSION: 2.0

DESCRIPTION:
This tool evaluates password strength based on industry security standards
including NIST guidelines for password security. It provides a score,
letter grade, and actionable recommendations for improvement.

DISCLAIMER:
This tool is for educational purposes. No passwords are stored or transmitted.
All analysis happens locally on the user's machine.
"""

import re
import hashlib
import getpass
from datetime import datetime
from typing import Dict, Tuple, List

class PasswordStrengthChecker:
    """
    A professional password strength checker that evaluates passwords
    based on multiple security criteria and provides detailed feedback.
    """
    
    def __init__(self):
        """Initialize the password checker with security criteria."""
        self.max_score = 100
        self.common_passwords = self._load_common_passwords()
        self.breach_check_enabled = False
        
    def _load_common_passwords(self) -> set:
        """
        Load list of commonly used weak passwords.
        In production, this could be loaded from an external file.
        """
        common = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', 'letmein', 'trustno1', 'dragon', 'baseball',
            'iloveyou', 'admin', 'welcome', 'master', 'sunshine',
            'password123', 'password1', 'admin123', 'qwerty123',
            '12345', '123456789', 'football', 'whatever', 'shadow'
        }
        return common
    
    def check_length(self, password: str) -> Tuple[int, str]:
        """
        Evaluate password length based on NIST recommendations.
        NIST SP 800-63B recommends minimum 8 characters, encourages longer.
        """
        length = len(password)
        
        if length >= 16:
            return 25, "Excellent: 16+ characters (exceeds NIST recommendation)"
        elif length >= 12:
            return 20, "Good: 12-15 characters meets security standards"
        elif length >= 8:
            return 10, "Minimum: 8-11 characters (meets basic requirements)"
        else:
            return 0, f"Too short: {length} characters (NIST minimum is 8)"
    
    def check_character_diversity(self, password: str) -> Tuple[int, List[str]]:
        """
        Check for different character types in the password.
        """
        score = 0
        checks_passed = []
        checks_failed = []
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 10
            checks_passed.append("Uppercase letters (A-Z)")
        else:
            checks_failed.append("Uppercase letters (A-Z)")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 10
            checks_passed.append("Lowercase letters (a-z)")
        else:
            checks_failed.append("Lowercase letters (a-z)")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 10
            checks_passed.append("Numbers (0-9)")
        else:
            checks_failed.append("Numbers (0-9)")
        
        # Check for special characters
        special_chars = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]'
        if re.search(special_chars, password):
            score += 10
            checks_passed.append("Special characters (!@#$% etc.)")
        else:
            checks_failed.append("Special characters (!@#$%^&*)")
        
        return score, checks_passed, checks_failed
    
    def check_common_patterns(self, password: str) -> Tuple[int, List[str]]:
        """
        Check for common weak patterns like sequential characters,
        repeated characters, or keyboard patterns.
        """
        score = 20
        warnings = []
        password_lower = password.lower()
        
        # Check against common password list
        if password_lower in self.common_passwords:
            score = 0
            warnings.append("CRITICAL: This is a commonly used weak password")
            return score, warnings
        
        # Check for sequential characters
        sequences = ['123456', 'abcdef', 'qwerty', 'asdfgh', 'zxcvbn']
        for seq in sequences:
            if seq in password_lower:
                score -= 10
                warnings.append(f"Contains sequential pattern '{seq}'")
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', password):
            score -= 10
            warnings.append("Contains repeated characters (e.g., 'aaaa')")
        
        # Check for keyboard row patterns
        keyboard_rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                if row[i:i+4] in password_lower:
                    score -= 10
                    warnings.append(f"Contains keyboard pattern '{row[i:i+4]}'")
                    break
        
        # Check if password contains username-like patterns
        if len(password) > 4 and password_lower.isalpha():
            score -= 5
            warnings.append("Contains only letters (add numbers or symbols)")
        
        return max(0, score), warnings
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits.
        Higher entropy means stronger password.
        """
        charset_size = 0
        character_sets = {
            'lowercase': 26 if re.search(r'[a-z]', password) else 0,
            'uppercase': 26 if re.search(r'[A-Z]', password) else 0,
            'digits': 10 if re.search(r'\d', password) else 0,
            'special': 32 if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password) else 0
        }
        
        charset_size = sum(character_sets.values())
        
        if charset_size == 0:
            return 0.0
        
        entropy = len(password) * (charset_size.bit_length())
        return round(entropy, 2)
    
    def evaluate(self, password: str) -> Dict:
        """
        Main evaluation function that combines all checks and returns
        a comprehensive report.
        """
        if not password:
            return {
                'score': 0,
                'grade': 'F',
                'strength': 'INVALID',
                'entropy': 0,
                'feedback': ['No password provided'],
                'warnings': [],
                'passed_checks': []
            }
        
        results = {}
        
        # Length check
        length_score, length_feedback = self.check_length(password)
        
        # Character diversity check
        diversity_score, passed, failed = self.check_character_diversity(password)
        
        # Common patterns check
        pattern_score, warnings = self.check_common_patterns(password)
        
        # Calculate total score
        total_score = length_score + diversity_score + pattern_score
        total_score = min(total_score, self.max_score)
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Determine grade and strength
        if total_score >= 90:
            grade = 'A+'
            strength = 'EXCELLENT'
            summary = 'Exceptionally strong password. Highly secure.'
        elif total_score >= 80:
            grade = 'A'
            strength = 'VERY STRONG'
            summary = 'Very strong password. Suitable for sensitive accounts.'
        elif total_score >= 70:
            grade = 'B'
            strength = 'STRONG'
            summary = 'Strong password. Good for most applications.'
        elif total_score >= 60:
            grade = 'C'
            strength = 'MODERATE'
            summary = 'Moderate password. Consider improvement.'
        elif total_score >= 45:
            grade = 'D'
            strength = 'WEAK'
            summary = 'Weak password. Should be improved.'
        elif total_score >= 25:
            grade = 'E'
            strength = 'VERY WEAK'
            summary = 'Very weak password. Not recommended.'
        else:
            grade = 'F'
            strength = 'CRITICAL'
            summary = 'Critically weak password. Do not use.'
        
        # Compile feedback
        feedback = [length_feedback]
        feedback.extend([f"Missing: {item}" for item in failed])
        feedback.extend(warnings)
        
        results = {
            'score': total_score,
            'grade': grade,
            'strength': strength,
            'summary': summary,
            'entropy': entropy,
            'password_length': len(password),
            'feedback': [f for f in feedback if f],
            'passed_checks': passed,
            'warnings': warnings,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return results
    
    def generate_report(self, password: str, results: Dict, save_to_file: bool = False) -> str:
        """
        Generate a formatted report of the password evaluation.
        """
        report_lines = []
        report_lines.append("=" * 65)
        report_lines.append("PASSWORD STRENGTH ASSESSMENT REPORT")
        report_lines.append("=" * 65)
        report_lines.append(f"Generated: {results['timestamp']}")
        report_lines.append(f"Password Length: {results['password_length']} characters")
        report_lines.append(f"Entropy: {results['entropy']} bits")
        report_lines.append("")
        report_lines.append("-" * 65)
        report_lines.append("SCORING SUMMARY")
        report_lines.append("-" * 65)
        report_lines.append(f"Total Score: {results['score']}/100")
        report_lines.append(f"Grade: {results['grade']}")
        report_lines.append(f"Strength Level: {results['strength']}")
        report_lines.append(f"Assessment: {results['summary']}")
        report_lines.append("")
        
        if results['passed_checks']:
            report_lines.append("-" * 65)
            report_lines.append("PASSED SECURITY CHECKS")
            report_lines.append("-" * 65)
            for check in results['passed_checks']:
                report_lines.append(f"  [+] {check}")
            report_lines.append("")
        
        if results['feedback']:
            report_lines.append("-" * 65)
            report_lines.append("IMPROVEMENT SUGGESTIONS")
            report_lines.append("-" * 65)
            for suggestion in results['feedback']:
                report_lines.append(f"  [!] {suggestion}")
            report_lines.append("")
        
        if results['warnings']:
            report_lines.append("-" * 65)
            report_lines.append("SECURITY WARNINGS")
            report_lines.append("-" * 65)
            for warning in results['warnings']:
                report_lines.append(f"  [X] {warning}")
            report_lines.append("")
        
        report_lines.append("=" * 65)
        report_lines.append("NIST SP 800-63B GUIDELINES REFERENCE")
        report_lines.append("=" * 65)
        report_lines.append("- Minimum password length: 8 characters")
        report_lines.append("- Longer passwords (12-16 chars) recommended")
        report_lines.append("- Allow all printable ASCII characters")
        report_lines.append("- Check against known weak passwords")
        report_lines.append("- No composition rules (complexity not required but beneficial)")
        report_lines.append("")
        report_lines.append("=" * 65)
        report_lines.append("DISCLAIMER")
        report_lines.append("=" * 65)
        report_lines.append("This assessment is for educational purposes only.")
        report_lines.append("The password was not stored or transmitted.")
        report_lines.append("Always use unique passwords for different services.")
        report_lines.append("Consider using a password manager for strong unique passwords.")
        report_lines.append("=" * 65)
        
        report = "\n".join(report_lines)
        
        if save_to_file:
            filename = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {filename}")
        
        return report


def main():
    """
    Main function to run the password strength checker.
    """
    print("=" * 65)
    print("PROFESSIONAL PASSWORD STRENGTH CHECKER")
    print("NIST SP 800-63B Compliant Security Assessment")
    print("=" * 65)
    print("\nThis tool evaluates password security based on industry standards.")
    print("Your password is NOT stored or transmitted.\n")
    
    checker = PasswordStrengthChecker()
    
    while True:
        print("-" * 65)
        use_hidden = input("Enable hidden password input? (y/n): ").lower()
        
        if use_hidden == 'y':
            password = getpass.getpass("Enter password to evaluate: ")
        else:
            password = input("Enter password to evaluate: ")
        
        if not password:
            print("No password entered. Please try again.")
            continue
        
        # Evaluate password
        results = checker.evaluate(password)
        
        # Generate and display report
        report = checker.generate_report(password, results, save_to_file=False)
        print(report)
        
        # Ask to save report
        save = input("\nSave this report to file? (y/n): ").lower()
        if save == 'y':
            checker.generate_report(password, results, save_to_file=True)
        
        # Ask to continue or exit
        print("\n" + "-" * 65)
        another = input("Evaluate another password? (y/n): ").lower()
        if another != 'y':
            print("\nThank you for using Password Strength Checker.")
            print("Stay secure!")
            break


if __name__ == "__main__":
    main()