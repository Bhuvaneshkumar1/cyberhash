"""
Rule Engine v2 for CyberHash — Modular, composable password mutation engine.
"""

import sys
import logging
from pathlib import Path
from typing import List, Callable, Set, Optional, Dict

# Individual Rule Transformations

def transform_lowercase(w: str) -> str:
    return w.lower()

def transform_uppercase(w: str) -> str:
    return w.upper()

def transform_capitalize(w: str) -> str:
    return w.capitalize()

def transform_titlecase(w: str) -> str:
    return w.title()

def transform_reverse(w: str) -> str:
    return w[::-1]

def transform_append_digits(w: str) -> List[str]:
    return [w + "1", w + "123", w + "1234", w + "777", w + "007"]

def transform_prepend_digits(w: str) -> List[str]:
    return ["1" + w, "123" + w, "007" + w]

def transform_append_symbols(w: str) -> List[str]:
    return [w + "!", w + "@", w + "#", w + "$", w + "!", w + "!?"]

def transform_prepend_symbols(w: str) -> List[str]:
    return ["!" + w, "@" + w, "#" + w]

def transform_leetspeak(w: str) -> List[str]:
    """
    Generate leetspeak variants of input string.
    """
    leet_map = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['$'],
        't': ['7']
    }
    results = []
    
    # Simple direct replacement
    v1 = list(w)
    for i, char in enumerate(v1):
        c_lower = char.lower()
        if c_lower in leet_map:
            v1[i] = leet_map[c_lower][0]
    results.append("".join(v1))

    # All replacement
    v2 = list(w)
    for i, char in enumerate(v2):
        c_lower = char.lower()
        if c_lower in leet_map:
            v2[i] = leet_map[c_lower][-1]
    results.append("".join(v2))

    return results

def transform_substitute(w: str) -> List[str]:
    """
    Common character substitutions.
    """
    subs = []
    subs.append(w.replace("a", "@").replace("A", "@"))
    subs.append(w.replace("e", "3").replace("E", "3"))
    subs.append(w.replace("o", "0").replace("O", "0"))
    subs.append(w.replace("s", "$").replace("S", "$"))
    subs.append(w.replace("i", "1").replace("I", "1"))
    return subs

def transform_year_suffix(w: str) -> List[str]:
    years = ["2023", "2024", "2025", "2026", "2022", "2021"]
    return [w + yr for yr in years]

def transform_numeric_suffixes(w: str) -> List[str]:
    nums = ["1", "12", "123", "1234", "12345", "01", "99"]
    return [w + n for n in nums]

def transform_password_suffixes(w: str) -> List[str]:
    suffixes = ["123!", "@123", "!123", "123456", "#1", "!2024"]
    return [w + s for s in suffixes]


# Registry of available rules
AVAILABLE_RULES: Dict[str, Callable[[str], List[str]]] = {
    "lowercase": lambda w: [transform_lowercase(w)],
    "uppercase": lambda w: [transform_uppercase(w)],
    "capitalize": lambda w: [transform_capitalize(w)],
    "titlecase": lambda w: [transform_titlecase(w)],
    "reverse": lambda w: [transform_reverse(w)],
    "append_digits": transform_append_digits,
    "prepend_digits": transform_prepend_digits,
    "append_symbols": transform_append_symbols,
    "prepend_symbols": transform_prepend_symbols,
    "leetspeak": transform_leetspeak,
    "substitute": transform_substitute,
    "year_suffix": transform_year_suffix,
    "numeric_suffixes": transform_numeric_suffixes,
    "password_suffixes": transform_password_suffixes,
}


class RuleEngine:
    """
    Composable mutation rule engine for password cracking.
    """

    def __init__(
        self,
        depth: int = 1,
        max_candidates: int = 500,
        rules_file: Optional[Path] = None
    ):
        """
        Initialize RuleEngine.

        :param depth: Composition depth (number of rules to chain).
        :param max_candidates: Ceiling on generated candidates to prevent explosion.
        :param rules_file: Optional path to file defining enabled rules.
        """
        self.depth: int = max(1, depth)
        self.max_candidates: int = max_candidates
        self.enabled_rule_names: List[str] = list(AVAILABLE_RULES.keys())

        if rules_file:
            self.load_rules_file(rules_file)

    def load_rules_file(self, rules_file: Path) -> None:
        """
        Load enabled rule names from a text file.

        :param rules_file: Path object to rules file.
        :raises ValueError: If rules file is invalid or empty.
        """
        if not rules_file.exists() or not rules_file.is_file():
            console_msg = f"Invalid rules file: {rules_file} (File not found)"
            logging.error(console_msg)
            raise ValueError(console_msg)

        enabled = []
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                for line in f:
                    name = line.strip().lower()
                    if name and not name.startswith("#"):
                        if name in AVAILABLE_RULES:
                            enabled.append(name)
                        else:
                            logging.warning(f"Unknown rule name in rules file: '{name}'")
        except Exception as e:
            raise ValueError(f"Failed to parse rules file '{rules_file}': {e}")

        if not enabled:
            raise ValueError(f"Rules file '{rules_file}' contains no valid rule definitions.")

        self.enabled_rule_names = enabled

    def mutate_single_pass(self, words: List[str]) -> List[str]:
        """
        Apply enabled rules to a list of word candidates for one pass.

        :param words: List of input words.
        :return: List of mutated words.
        """
        new_words: List[str] = []
        seen: Set[str] = set()

        for w in words:
            for rule_name in self.enabled_rule_names:
                rule_fn = AVAILABLE_RULES[rule_name]
                try:
                    results = rule_fn(w)
                    for res in results:
                        if res and res not in seen:
                            seen.add(res)
                            new_words.append(res)
                            if len(new_words) >= self.max_candidates:
                                return new_words
                except Exception as e:
                    logging.debug(f"Rule '{rule_name}' failed on '{w}': {e}")

        return new_words

    def generate_mutations(self, word: str) -> List[str]:
        """
        Generate composable mutations for a given input word up to target depth.
        Guarantees deduplication and never returns the original word.

        :param word: Original input word string.
        :return: Deduplicated list of mutated candidates (excluding original word).
        """
        if not word:
            return []

        all_mutations: List[str] = []
        seen: Set[str] = {word}  # Ensure original word is never returned
        current_layer: List[str] = [word]

        for _ in range(self.depth):
            next_layer = self.mutate_single_pass(current_layer)
            filtered_next: List[str] = []
            for item in next_layer:
                if item not in seen:
                    seen.add(item)
                    all_mutations.append(item)
                    filtered_next.append(item)
                    if len(all_mutations) >= self.max_candidates:
                        return all_mutations
            current_layer = filtered_next
            if not current_layer:
                break

        return all_mutations


# Backward Compatibility Utility Functions

def apply_rules(word: str) -> List[str]:
    """
    Legacy wrapper applying basic mutations to a string word.
    """
    engine = RuleEngine(depth=1)
    return engine.generate_mutations(word)


def mutations(word: bytes) -> List[bytes]:
    """
    Legacy wrapper applying binary mutations.
    """
    text = word.decode(errors="ignore")
    engine = RuleEngine(depth=1)
    return [m.encode() for m in engine.generate_mutations(text)]
