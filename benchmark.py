#!/usr/bin/env python3
"""
Prints recall / false-positive metrics for the injection detector against
the labeled corpus in tests/attack_corpus.py. Useful for quickly checking
the impact of a new regex pattern or threshold change.

Usage:
    python benchmark.py
"""

from guardrails.detector import InjectionDetector
from tests.attack_corpus import ATTACKS, BENIGN


def main():
    detector = InjectionDetector()

    caught = []
    missed = []
    for attack in ATTACKS:
        result = detector.scan(attack)
        (caught if result.is_suspicious else missed).append((attack, result))

    false_positives = []
    true_negatives = []
    for benign in BENIGN:
        result = detector.scan(benign)
        (false_positives if result.is_suspicious else true_negatives).append((benign, result))

    recall = len(caught) / len(ATTACKS)
    fp_rate = len(false_positives) / len(BENIGN)

    print("=" * 60)
    print("LLM Guardrails - Detector Benchmark")
    print("=" * 60)
    print(f"Attacks in corpus : {len(ATTACKS)}")
    print(f"Caught            : {len(caught)}  (recall {recall:.1%})")
    print(f"Missed            : {len(missed)}")
    print()
    print(f"Benign prompts    : {len(BENIGN)}")
    print(f"False positives   : {len(false_positives)}  (rate {fp_rate:.1%})")
    print("=" * 60)

    if missed:
        print("\nMissed attacks:")
        for text, result in missed:
            print(f"  - {text!r} (score={result.score:.2f})")

    if false_positives:
        print("\nFalse positives:")
        for text, result in false_positives:
            print(f"  - {text!r} (score={result.score:.2f}, categories={result.matched_categories})")


if __name__ == "__main__":
    main()
