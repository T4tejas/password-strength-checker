import hashlib
import bcrypt
import re

# ---------------------------
# 1. Hashing Functions
# ---------------------------

def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# ---------------------------
# 2. Password Strength Checks
# ---------------------------

def is_common_password(password: str) -> bool:
    # safe, tiny example list
    common_pw = ["123456", "password", "admin", "qwerty", "123123", "hello"]
    return password.lower() in common_pw

def check_strength(password: str) -> dict:
    score = 0
    issues = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        issues.append("Password is too short (use 12+ characters).")

    # Upper/lowercase
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("Use a mix of uppercase and lowercase letters.")

    # Numbers
    if re.search(r"[0-9]", password):
        score += 1
    else:
        issues.append("Add numbers to increase complexity.")

    # Symbols
    if re.search(r"[\W_]", password):
        score += 1
    else:
        issues.append("Add symbols like ! @ # $ % ^ & *.")

    # Common password check
    if is_common_password(password):
        issues.append("This password is very common and easily guessed.")
    else:
        score += 1

    # Final rating
    if score >= 6:
        strength = "Strong"
    elif 3 <= score < 6:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {"strength": strength, "score": score, "issues": issues}

# ---------------------------
# 3. Program Flow
# ---------------------------

if __name__ == "__main__":
    print("=== Password Defense Tool ===")

    user_pass = input("Enter a password to evaluate: ")

    print("\n--- Hashing Results ---")
    print("SHA-256 Hash:", hash_sha256(user_pass))
    print("bcrypt Hash:", hash_bcrypt(user_pass))

    print("\n--- Strength Analysis ---")
    analysis = check_strength(user_pass)

    print("Strength:", analysis["strength"])
    print("Score:", analysis["score"])

    print("\nIssues found:")
    for issue in analysis["issues"]:
        print(" -", issue)
