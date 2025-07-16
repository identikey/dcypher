# AllHands/OpenHands Configuration for DCypher

This document explains the AllHands (OpenHands) AI assistant configuration we've set up for the DCypher project.

## 📁 Configuration Files Created

### 1. `config.toml` - Main Configuration

The primary configuration file that tells AllHands about our project structure and preferences:

- **Excluded Directories**: `vendor/`, build artifacts, cache directories
- **Python Project Setup**: Uses `uv` package manager and `pytest` for testing
- **Development Tools**: Configures `just` task runner and `ruff` linting
- **Runtime Environment**: Python 3.12 with necessary system dependencies
- **Security Settings**: Appropriate restrictions for a cryptographic project

### 2. `.openhands-instructions.md` - Human-Readable Guidance

Detailed instructions that provide context about:

- Project architecture and cryptographic concepts
- Development workflow and best practices
- Security considerations for crypto operations
- File organization and focus areas
- Quick start guide for new contributors

### 3. Updated `.gitignore`

Added AllHands cache directory to prevent committing temporary files.

## 🎯 What This Configuration Achieves

### ✅ **Proper Project Understanding**

- AllHands knows this is a Python project using `uv` and `just`
- Understands the cryptographic nature and security requirements
- Recognizes test structure (`pytest` with parallel execution)

### ✅ **Directory Awareness**  

- **Won't modify** `vendor/` (git submodules for OpenFHE, liboqs)
- **Focuses on** `src/` and `tests/` for code changes
- **Avoids** build artifacts and cache directories

### ✅ **Optimized Workflow**

- Knows to run tests with `uv run pytest -n auto` for parallel execution
- Understands `just` commands for development tasks
- Configured for proper Python path and environment setup

### ✅ **Security Awareness**

- Understands this is a cryptographic project requiring careful handling
- Knows about performance implications of crypto operations
- Aware of timing attack and side-channel considerations

## 🚀 Using AllHands with DCypher

### Starting AllHands

Run the AllHands Docker command from your `Justfile`:

```bash
just doit
```

This will:

1. Pull the latest AllHands runtime image
2. Mount your workspace with proper volume settings
3. Start AllHands on <http://localhost:3000>
4. Apply the configuration automatically

### First-Time Setup

When AllHands starts, it will:

- Read `config.toml` for project configuration
- Use `.openhands-instructions.md` for additional context
- Set up the runtime with `uv`, `just`, and system dependencies
- Configure the Python environment with proper paths

### Typical Interactions

AllHands will now understand commands like:

- "Run the tests in parallel" → `uv run pytest -n auto`
- "Check code quality" → `uv run ruff check src/ tests/`
- "Build the dependencies" → `just build-all`
- "Start development environment" → `just dev-up`

## 🔧 Configuration Details

### Runtime Setup

The sandbox will automatically install:

- `uv` package manager
- `just` task runner  
- Build tools (cmake, gcc, etc.)
- SSL and crypto development libraries

### Environment Variables

- `PYTHONPATH=/workspace/src` - Proper Python import paths
- `UV_SYSTEM_PYTHON=1` - Use system Python with uv
- Updated `PATH` for installed tools

### File Restrictions

- Only allows relevant file types (`.py`, `.toml`, `.md`, etc.)
- 50MB upload limit for safety
- Excludes vendor directories from file operations

## 📚 Reference Links

Based on [AllHands/OpenHands documentation](https://docs.all-hands.dev/):

- [Configuration Options](https://docs.all-hands.dev/modules/usage/configuration-options)
- [Custom Sandbox](https://docs.all-hands.dev/modules/usage/how-to/custom-sandbox-guide)  
- [Repository Customization](https://docs.all-hands.dev/usage/how-to/github-action#add-custom-repository-settings)

## 💡 Tips for Working with AllHands

1. **Be Specific**: Reference file paths and commands explicitly
2. **Use Project Context**: AllHands now knows about proxy recryption and OpenFHE
3. **Test Incrementally**: Ask for small changes and test them before proceeding
4. **Security First**: AllHands understands this is a crypto project requiring care

The configuration ensures AllHands can effectively assist with DCypher development while respecting the project's structure and security requirements.
