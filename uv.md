# XDP Manager - UV Project Configuration
# Fast Python package management with UV

# Install the project in development mode:
# uv pip install -e .

# Install with all optional dependencies:
# uv pip install -e ".[dev,docs,test]"

# Install from requirements.txt:
# uv pip install -r requirements.txt

# Create virtual environment:
# uv venv
# source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate     # Windows

# Sync dependencies:
# uv pip sync requirements.txt

# Add new dependency:
# uv add package_name

# Remove dependency:  
# uv remove package_name

# Generate lock file:
# uv pip compile pyproject.toml -o requirements.lock

# Update all dependencies:
# uv pip install --upgrade-all

# Run the application:
# uv run xdp-manager --help
# uv run python -m xdp_manager.cli --help