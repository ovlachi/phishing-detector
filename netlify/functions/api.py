import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from mangum import Mangum
    from src.api.main import app
    
    # Create Mangum adapter for Netlify
    handler = Mangum(app, lifespan="off")
    
except ImportError as e:
    print(f"Import error: {e}")
    
    def handler(event, context):
        return {
            'statusCode': 500,
            'body': f'Import error: {e}'
        }
