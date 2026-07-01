import sys
import os


def check_dependencies():
    """Check if all required GUI dependencies are installed."""
    missing = []

    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")

    try:
        import PIL
    except ImportError:
        missing.append("Pillow")

    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib")

    try:
        import numpy
    except ImportError:
        missing.append("numpy")

    if missing:
        print("\nMissing required dependencies:\n")
        for pkg in missing:
            print(f"  - {pkg}")

        print("\nInstall them using:")
        print("pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":

    # Check required packages
    check_dependencies()

    # Add project root to Python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    # Import application after dependency check
    from services.data_provider import DataProvider
    from app import App

    print("[+] Initializing RAM Forensics Service Layer...")

    output_dir = os.path.join(current_dir, "output")
    service = DataProvider(output_dir=output_dir)

    print("[+] Launching RAM Forensics Dashboard...")

    app = App(data_service=service)

    try:
        app.mainloop()
        print("[+] Application closed successfully.")
    except KeyboardInterrupt:
        print("\n[!] Application terminated by user.")
    except Exception as e:
        print(f"\n[-] Application crashed: {e}")
        sys.exit(1)