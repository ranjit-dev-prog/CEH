import string
import random
import sys

# Password strength evaluation
def check_password_strength(password):
    strength = 0
    reasons = []

    # Length
    if len(password) >= 12:
        strength += 2
    elif len(password) >= 8:
        strength += 1
    else:
        reasons.append("Too short (<8 characters)")

    # Character variety
    if any(c.islower() for c in password):
        strength += 1
    else:
        reasons.append("No lowercase letters")

    if any(c.isupper() for c in password):
        strength += 1
    else:
        reasons.append("No uppercase letters")

    if any(c.isdigit() for c in password):
        strength += 1
    else:
        reasons.append("No numbers")

    if any(c in string.punctuation for c in password):
        strength += 1
    else:
        reasons.append("No special characters")

    # Common patterns
    common_patterns = ["123", "password", "admin", "qwerty", "letmein"]
    if any(pat in password.lower() for pat in common_patterns):
        reasons.append("Contains common patterns or words")

    # Repeated or sequential characters
    if any(password[i] == password[i+1] for i in range(len(password)-1)):
        reasons.append("Contains repeated characters")
    if password.isdigit() and (password in "0123456789" or password in "9876543210"):
        reasons.append("Sequential numeric password")

    # Strength level
    if strength <= 2 or reasons:
        level = "Weak"
    elif strength <= 4:
        level = "Moderate"
    else:
        level = "Strong"

    return level, reasons

# Suggest strong password
def suggest_password(length=16):
    all_chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

# Main function
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <password_to_check>")
        sys.exit(1)

    password = sys.argv[1]
    level, reasons = check_password_strength(password)
    print(f"\nPassword Strength: {level}")

    if level != "Strong":
        if reasons:
            print("Reasons why it's weak or moderate:")
            for r in reasons:
                print(" -", r)
        print("\nSuggested Strong Password:", suggest_password())
    else:
        print("✅ Your password is already strong!")

if __name__ == "__main__":
    main()
