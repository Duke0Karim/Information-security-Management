import itertools
import string
import os

# Hardcoded correct password (as per the assignment)
CORRECT_PASSWORD = "abcba"

# Path to the dictionary file
DICTIONARY_PATH = r"password.list"

def load_dictionary():
    """Loads the dictionary file into a list."""
    if not os.path.exists(DICTIONARY_PATH):
        print(f"Error: Dictionary file not found at {DICTIONARY_PATH}")
        return []
    
    with open(DICTIONARY_PATH, "r", encoding="utf-8") as file:
        return [line.strip() for line in file.readlines()]

def dictionary_attack(dictionary):
    """Attempts to crack the password using a dictionary attack."""
    print("Starting dictionary attack...")

    for word in dictionary:
        print(f"Trying: {word}")
        if word == CORRECT_PASSWORD:
            print(f"Password found using dictionary attack: {word}")
            return True

    print("Dictionary attack failed.")
    return False

def brute_force_attack():
    """Attempts to crack the password using brute force (all possible 5-letter combinations)."""
    print("Starting brute force attack...")

    characters = string.ascii_letters  # A-Z, a-z
    for attempt in itertools.product(characters, repeat=5):
        guess = "".join(attempt)
        print(f"Trying: {guess}")
        if guess == CORRECT_PASSWORD:
            print(f"Password found using brute force: {guess}")
            return True

    print("Brute force attack failed.")
    return False

def main():
    print("Password Cracking Program")

    # Load dictionary from file
    dictionary = load_dictionary()

    # Step 1: Dictionary Attack
    if not dictionary_attack(dictionary):
        # Step 2: Brute Force Attack if dictionary attack fails
        brute_force_attack()

if __name__ == "__main__":
    main()
