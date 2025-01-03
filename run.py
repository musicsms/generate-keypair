#!/usr/bin/env python3
import os
import sys
import streamlit.web.cli as stcli
from pathlib import Path

def run_streamlit():
    # Get the absolute path to the app.py file
    current_dir = Path(__file__).parent
    app_path = current_dir / "src" / "frontend" / "app.py"
    
    if not app_path.exists():
        print(f"Error: Could not find {app_path}")
        sys.exit(1)

    # Add the src directory to Python path
    src_path = str(current_dir / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    # Construct Streamlit run command
    sys.argv = [
        "streamlit",
        "run",
        str(app_path),
        "--theme.primaryColor=#4CAF50",
        "--theme.backgroundColor=#FFFFFF",
        "--theme.secondaryBackgroundColor=#F0F2F6",
        "--theme.textColor=#262730",
        "--server.port=8501",
        "--server.address=0.0.0.0",  # Bind to all interfaces for production
    ]

    # Run Streamlit
    try:
        sys.exit(stcli.main())
    except Exception as e:
        print(f"Failed to start Streamlit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_streamlit()