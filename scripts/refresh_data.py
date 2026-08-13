import sys
import os

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)

from incidents.incident_manager import (
    create_incidents,
    save_incidents
)

from incidents.attack_chain_correlator import (
    correlate_attack_chains,
    save_attack_chains
)


def refresh_security_data():

    print("=" * 70)
    print("SECURITY DATA REFRESH")
    print("=" * 70)

    # =====================================================
    # Step 1 - Generate incidents
    # =====================================================

    print("[1/2] Generating incidents...")

    incidents = create_incidents()

    save_incidents(
        incidents
    )

    print(
        f"[+] {len(incidents)} incidents generated."
    )

    # =====================================================
    # Step 2 - Generate attack chains
    # =====================================================

    print("[2/2] Correlating attack chains...")

    chains = correlate_attack_chains(
        incidents
    )

    save_attack_chains(
        chains
    )

    print(
        f"[+] {len(chains)} attack chains generated."
    )

    print("=" * 70)
    print("REFRESH COMPLETE")
    print("=" * 70)

    return {
        "incidents": len(incidents),
        "chains": len(chains)
    }


if __name__ == "__main__":

    refresh_security_data()
