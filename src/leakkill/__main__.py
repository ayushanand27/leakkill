from .cli import main_cli

if __name__ == "__main__":  # guard needed: parallel scanning re-imports this module on Windows/macOS
    main_cli()
