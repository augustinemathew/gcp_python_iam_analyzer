"""Stage s02: Fix registry metadata (iam_prefix, display_name) using Gemini.

Delegates to existing build/fix_registry_metadata.py logic.
Many services have service_id != iam_prefix (e.g. kms → cloudkms).
"""

from __future__ import annotations


def main() -> None:
    """Run the existing fix_registry_metadata script."""
    # Delegate to existing script to avoid duplicating Gemini prompt logic
    from build.fix_registry_metadata import main as fix_main

    fix_main()


if __name__ == "__main__":
    main()
