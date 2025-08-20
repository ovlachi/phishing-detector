import sys
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

def find_credentials():
    """Look for test credentials in the codebase"""
    
    print("🔍 Looking for Test Credentials")
    print("=" * 40)
    
    try:
        # Check main.py for test user creation
        main_file = Path(project_root) / "src" / "api" / "main.py"
        
        if main_file.exists():
            with open(main_file, 'r') as f:
                content = f.read()
                
                # Look for test user creation patterns
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'testuser' in line.lower() or 'test_user' in line.lower():
                        print(f"Line {i+1}: {line.strip()}")
                    if 'password' in line.lower() and ('test' in line.lower() or 'admin' in line.lower()):
                        print(f"Line {i+1}: {line.strip()}")
                    if 'create_test_user' in line:
                        # Print surrounding lines for context
                        start = max(0, i-2)
                        end = min(len(lines), i+3)
                        print(f"\nFound test user creation around line {i+1}:")
                        for j in range(start, end):
                            print(f"  {j+1}: {lines[j]}")
        
        # Check database.py
        db_file = Path(project_root) / "src" / "api" / "database.py"
        if db_file.exists():
            print(f"\n📋 Checking database.py...")
            with open(db_file, 'r') as f:
                content = f.read()
                if 'testuser' in content or 'admin' in content:
                    print("Found user references in database.py")
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    find_credentials()