#!/usr/bin/env python3
"""
Simple password strength checker.
Usage:
  python checker.py "YourP@ssw0rd!"
"""

import re
import argparse
import json

COMMON = {
    # small sample; replace/extend with a larger list (do NOT commit huge breached lists).
    "123456", "password", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome"
}

def score_password(pw: str):
    length = len(pw)
    score = 0
    reasons = []

    # length
    if length >= 12:
        score += 3
    elif length >= 8:
        score += 2
    elif length >= 6:
        score += 1
    else:
        score += 0
        reasons.append("password too short (<6)")

    # character classes
    classes = 0
    classes += bool(re.search(r'[a-z]', pw))
    classes += bool(re.search(r'[A-Z]', pw))
    classes += bool(re.search(r'\d', pw))
    classes += bool(re.search(r'[^A-Za-z0-9]', pw))
    score += classes  # 0-4

    if classes < 3:
        reasons.append("use a mix of uppercase, lowercase, digits and symbols")

    # repeated sequences
    if re.search(r'(.)\1\1', pw):
        score -= 1
        reasons.append("repeated characters")

    # keyboard patterns (simple)
    if re.search(r'1234|abcd|qwer|asdf', pw.lower()):
        score -= 1
        reasons.append("contains simple sequence")

    # common password
    if pw.lower() in COMMON:
        score = 0
        reasons.append("common password")

    # clamp
    score = max(0, min(10, score))

    # classification
    if score >= 8:
        strength = "very strong"
    elif score >= 6:
        strength = "strong"
    elif score >= 4:
        strength = "moderate"
    elif score >= 2:
        strength = "weak"
    else:
        strength = "very weak"

    return {
        "password_length": length,
        "score": score,
        "strength": strength,
        "reasons": reasons
    }

def main():
    parser = argparse.ArgumentParser(description="Password strength checker")
    parser.add_argument("password", help="Password to check (wrap in quotes)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()
    res = score_password(args.password)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Length: {res['password_length']}, Score: {res['score']}, Strength: {res['strength']}")
        if res['reasons']:
            print("Notes:")
            for r in res['reasons']:
                print(" -", r)

if __name__ == "__main__":
    main()
