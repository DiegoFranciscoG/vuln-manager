"""Fails the build when line coverage in a ReportGenerator TextSummary is below the threshold.

Usage: python3 scripts/check-coverage.py artifacts/coverage/report/Summary.txt 70
"""

import re
import sys


def main() -> int:
    summary_path, threshold = sys.argv[1], float(sys.argv[2])
    with open(summary_path, encoding="utf-8") as summary:
        match = re.search(r"Line coverage:\s*([\d.]+)%", summary.read())
    if match is None:
        print("No se encontró 'Line coverage' en el resumen.")
        return 1

    coverage = float(match.group(1))
    print(f"Cobertura de líneas (Domain + Application): {coverage:.1f} % (umbral {threshold:.0f} %)")
    return 0 if coverage >= threshold else 1


if __name__ == "__main__":
    sys.exit(main())
