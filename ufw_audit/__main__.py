"""
ufw-audit — tombstone release.

This package is deprecated. Use bodyguard-of-bits instead.
"""

import sys


def main() -> None:
    sys.stderr.write(
        "\n"
        "⚠  ufw-audit is deprecated and will no longer receive updates.\n"
        "\n"
        "   This project continues under a new name:\n"
        "   BOB — Bodyguard Of Bits\n"
        "\n"
        "   Uninstall ufw-audit and install the replacement:\n"
        "     pipx uninstall ufw-audit\n"
        "     pipx install bodyguard-of-bits\n"
        "\n"
        "   GitHub: https://github.com/Masbateno/bodyguard-of-bits\n"
        "\n"
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
