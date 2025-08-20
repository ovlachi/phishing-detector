import sys
import os
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

print("🔍 Checking Available Functions and Modules")
print("=" * 50)

# Check predict.py
try:
    from src.api import predict
    print("✅ src.api.predict module found")
    print("Available functions:", [func for func in dir(predict) if not func.startswith('_')])
except ImportError as e:
    print(f"❌ Cannot import src.api.predict: {e}")

# Check what's in src/features/
features_dir = os.path.join(project_root, "src", "features")
if os.path.exists(features_dir):
    print(f"\n📁 Contents of {features_dir}:")
    for file in os.listdir(features_dir):
        if file.endswith('.py'):
            print(f"   - {file}")
else:
    print(f"\n❌ {features_dir} does not exist")

# Check what's in src/
src_dir = os.path.join(project_root, "src")
if os.path.exists(src_dir):
    print(f"\n📁 Contents of {src_dir}:")
    for item in os.listdir(src_dir):
        print(f"   - {item}")

# Check main.py functions
try:
    from src.api import main
    print("\n✅ src.api.main module found")
    print("Available functions:", [func for func in dir(main) if not func.startswith('_') and callable(getattr(main, func))])
except ImportError as e:
    print(f"\n❌ Cannot import src.api.main: {e}")