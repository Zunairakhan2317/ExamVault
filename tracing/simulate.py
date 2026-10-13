"""Simulation script for collusion and tracing accuracy, saving matplotlib graphs to docs/ (Plan 5.8)."""
from __future__ import annotations

import random
from pathlib import Path
import matplotlib.pyplot as plt

from tracing.tardos import generate_bias_vector, generate_codeword, compute_scores


def run_simulation(num_users: int = 10, num_slots: int = 40, trials: int = 200) -> dict:
    """Run collusion simulation trials and measure detection rates."""
    biases = generate_bias_vector(num_slots)
    results = {}

    for colluder_count in range(1, 5):
        detected_count = 0
        for _ in range(trials):
            suspects = [generate_codeword(biases) for _ in range(num_users)]
            # Choose colluders
            colluders = random.sample(range(num_users), colluder_count)
            
            # Create colluded leaked word (majority or random choice between colluders)
            leaked_word = []
            for i in range(num_slots):
                chosen_colluder = random.choice(colluders)
                leaked_word.append(suspects[chosen_colluder][i])

            scores = compute_scores(suspects, leaked_word, biases)
            
            # Check if any actual colluder is in top accused suspects
            max_score_idx = scores.index(max(scores))
            if max_score_idx in colluders:
                detected_count += 1

        detection_rate = detected_count / trials
        results[colluder_count] = detection_rate

    return results


def generate_simulation_plots() -> Path:
    """Run simulation and save matplotlib graph into docs/."""
    docs_dir = Path("docs")
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    data = run_simulation(num_users=10, num_slots=40, trials=100)
    
    colluders = list(data.keys())
    rates = [data[c] * 100 for c in colluders]

    plt.figure(figsize=(8, 5))
    plt.plot(colluders, rates, marker='o', color='b', linestyle='-', linewidth=2)
    plt.title("Tardos Tracing: Detection Rate vs. Number of Colluders")
    plt.xlabel("Number of Colluders")
    plt.ylabel("Detection Rate (%)")
    plt.ylim(0, 105)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    output_path = docs_dir / "collusion_simulation.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


if __name__ == "__main__":
    path = generate_simulation_plots()
    print(f"Simulation graph saved to {path}")