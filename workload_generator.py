# Workload generator for benchmarks
# Generates test passwords and hashes for benchmarking

import hashlib
import random
import string
from typing import List, Tuple, Optional
from dataclasses import dataclass
from benchmark_harness import Workload


def hash_password(password: str, salt: Optional[str] = None) -> str:
    # Hash a password with optional salt
    if salt:
        return hashlib.sha256((salt + password).encode()).hexdigest()
    return hashlib.sha256(password.encode()).hexdigest()


# Config for brute-force workloads
@dataclass
class BruteForceWorkloadConfig:
    character_set: str
    min_length: int = 1
    max_length: int = 8
    num_targets: int = 5
    use_salt: bool = False


# Config for dictionary workloads
@dataclass
class DictionaryWorkloadConfig:
    wordlist_size: int = 1000
    min_word_length: int = 4
    max_word_length: int = 12
    character_set: str = string.ascii_lowercase + string.digits
    num_targets: int = 5
    use_salt: bool = False


class WorkloadGenerator:
    # Generates test workloads for benchmarking
    
    @staticmethod
    def generate_brute_force_workloads(
        config: BruteForceWorkloadConfig
    ) -> List[Workload]:
        # Generate brute-force test workloads
        workloads = []
        
        for _ in range(config.num_targets):
            # Generate a random password
            password_length = random.randint(config.min_length, config.max_length)
            password = ''.join(
                random.choice(config.character_set)
                for _ in range(password_length)
            )
            
            # Generate hash and optional salt
            salt = None
            if config.use_salt:
                salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            target_hash = hash_password(password, salt)
            
            workload = Workload(
                target_hash=target_hash,
                target_salt=salt,
                character_set=config.character_set,
                max_length=config.max_length,
                dictionary=None
            )
            
            workloads.append(workload)
        
        return workloads
    
    @staticmethod
    def generate_dictionary_workloads(
        config: DictionaryWorkloadConfig
    ) -> List[Tuple[Workload, List[str]]]:
        # Generate dictionary attack workloads
        workloads = []
        
        for _ in range(config.num_targets):
            # Generate a wordlist
            wordlist = []
            target_password = None
            
            for i in range(config.wordlist_size):
                word_length = random.randint(config.min_word_length, config.max_word_length)
                word = ''.join(
                    random.choice(config.character_set)
                    for _ in range(word_length)
                )
                wordlist.append(word)
                
                # Pick one as the target (not first, for variety)
                if target_password is None and i > config.wordlist_size // 10:
                    if random.random() < 0.1:
                        target_password = word
            
            # Use last word if no target was picked
            if target_password is None:
                target_password = wordlist[-1]
            
            # Generate hash and optional salt
            salt = None
            if config.use_salt:
                salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            target_hash = hash_password(target_password, salt)
            
            workload = Workload(
                target_hash=target_hash,
                target_salt=salt,
                character_set=config.character_set,
                max_length=0,
                dictionary=wordlist
            )
            
            workloads.append((workload, target_password))
        
        return workloads
    
    @staticmethod
    def generate_common_passwords_list(size: int = 1000) -> List[str]:
        # Generate list of common passwords for dictionary attacks
        common_passwords = []
        
        # Common numeric sequences
        for i in range(100, min(10000, size // 4)):
            common_passwords.append(str(i))
            common_passwords.append(f"password{i}")
            common_passwords.append(f"123456{i}")
        
        # Common words
        common_words = [
            "password", "123456", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "monkey",
            "1234567", "letmein", "trustno1", "dragon", "baseball",
            "iloveyou", "master", "sunshine", "ashley", "bailey",
            "passw0rd", "shadow", "123123", "654321", "superman"
        ]
        
        common_passwords.extend(common_words)
        
        # Variations on common words
        variations = []
        for word in common_words[:20]:
            variations.append(word + "1")
            variations.append(word + "123")
            variations.append(word.upper())
            variations.append(word.capitalize())
            variations.append(word.replace('a', '@').replace('o', '0'))
        
        common_passwords.extend(variations)
        
        # Keyboard patterns
        keyboard_patterns = [
            "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
            "1qaz2wsx", "qazwsx", "qwerty123"
        ]
        common_passwords.extend(keyboard_patterns)
        
        # Fill up to desired size with random passwords
        while len(common_passwords) < size:
            length = random.randint(6, 10)
            password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
            common_passwords.append(password)
        
        # Shuffle and return
        random.shuffle(common_passwords)
        return common_passwords[:size]
    
    @staticmethod
    def create_simple_test_workload() -> Workload:
        # Create a simple test workload with a known password
        test_password = "test123"
        test_hash = hash_password(test_password)
        
        return Workload(
            target_hash=test_hash,
            target_salt=None,
            character_set="abcdefghijklmnopqrstuvwxyz0123456789",
            max_length=7,
            dictionary=None
        )


if __name__ == "__main__":
    # Test the workload generator
    generator = WorkloadGenerator()
    
    print("Generating simple test workload...")
    simple_workload = generator.create_simple_test_workload()
    print(f"Target hash: {simple_workload.target_hash}")
    print(f"Character set: {simple_workload.character_set}")
    print(f"Max length: {simple_workload.max_length}")
    
    print("\nGenerating brute-force workloads...")
    bf_config = BruteForceWorkloadConfig(
        character_set="abcdefghijklmnopqrstuvwxyz0123456789",
        min_length=4,
        max_length=6,
        num_targets=3,
        use_salt=False
    )
    bf_workloads = generator.generate_brute_force_workloads(bf_config)
    print(f"Generated {len(bf_workloads)} brute-force workloads")
    
    print("\nGenerating dictionary workloads...")
    dict_config = DictionaryWorkloadConfig(
        wordlist_size=100,
        min_word_length=4,
        max_word_length=8,
        num_targets=2,
        use_salt=False
    )
    dict_workloads = generator.generate_dictionary_workloads(dict_config)
    print(f"Generated {len(dict_workloads)} dictionary workloads")
    
    print("\nGenerating common passwords list...")
    common_passwords = generator.generate_common_passwords_list(50)
    print(f"Generated {len(common_passwords)} common passwords")
    print(f"Sample: {common_passwords[:10]}")
