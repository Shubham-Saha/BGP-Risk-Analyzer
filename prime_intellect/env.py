"""Environment variable loading for Prime Intellect API credentials."""

import os
from pathlib import Path


def _load_dotenv():
    """Load key=value pairs from .env file into os.environ (if not already set)."""
    # .env lives in scanner/ (one level up from this package)
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # Don't overwrite real env vars; skip placeholder values
        if key and value and not value.startswith("your_"):
            os.environ.setdefault(key, value)


_load_dotenv()


def get_api_key() -> str:
    """Get API key from .env file, env var, or prompt interactively."""
    key = os.environ.get("PRIME_API_KEY")
    if key:
        print("  Using API key from .env / environment variable.")
        return key

    print("  PRIME_API_KEY not found in .env or environment.")
    key = input("  Enter your Prime Intellect API key: ").strip()
    if not key:
        print("  No API key provided. Returning to menu.")
        return ""
    return key


def get_team_id() -> str:
    """Get team ID from .env file, env var, or prompt interactively.

    The team ID is required so the API charges against the team wallet
    rather than the personal wallet.
    """
    team_id = os.environ.get("PRIME_TEAM_ID")
    if team_id:
        print(f"  Using team ID from .env / environment variable: {team_id}")
        return team_id

    print("  PRIME_TEAM_ID not found in .env or environment.")
    team_id = input("  Enter your Prime Intellect Team ID: ").strip()
    if not team_id:
        print("  No team ID provided. Returning to menu.")
        return ""
    return team_id
