"""Statistical analysis for Fantuan Network anonymity simulations.

The analyzer is deliberately dependency-free (Python standard library only)
so it can run in any offline environment. It consumes the JSON transcripts
produced by the Rust `fantuan-sim` collector and writes English reports.
"""

__version__ = "0.1.0"
