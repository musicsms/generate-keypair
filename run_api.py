import uvicorn
import sys
from pathlib import Path

def run_api():
    # Add the src directory to Python path
    current_dir = Path(__file__).parent
    src_path = str(current_dir / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    # Run the FastAPI application
    uvicorn.run(
        "api.main:app",
        host="localhost",
        port=8070,
        reload=True
    )

if __name__ == "__main__":
    run_api()
