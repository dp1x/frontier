"""Allow ``python -m frontier`` to invoke the CLI."""

from frontier.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
