# Contributing to Advocate

Thank you for your interest in contributing to Advocate! This document outlines how to contribute to the project.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- pip (preferably in a virtual environment)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JordanMilne/Advocate.git
   cd Advocate
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install the package in development mode:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks (optional but recommended):**
   ```bash
   pip install pre-commit
   pre-commit install
   ```

5. **Run the tests:**
   ```bash
   pytest
   ```

6. **Run with coverage:**
   ```bash
   pytest --cov=advocate --cov-report=html
   ```

## Code Style

### Linting

We use [Ruff](https://astral.sh/ruff) for linting. Run the linter with:

```bash
ruff check .
```

Most issues can be fixed automatically:

```bash
ruff check --fix .
```

### Type Checking

We use [mypy](https://mypy-lang.org/) for type checking. Run it with:

```bash
mypy advocate
```

### Formatting

Code formatting is handled by Ruff, which includes formatting rules similar to Black.

## Testing

### Running Tests

Run all tests with:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run specific tests:

```bash
pytest test/test_advocate.py::TestClass::test_method
```

### Writing Tests

When adding new features or fixing bugs, please include tests. Tests should:

- Be placed in the `test/` directory
- Use `pytest` style assertions
- Cover both happy paths and edge cases
- Include security-related test cases where applicable

## Pull Requests

### Creating a Pull Request

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** and commit them:
   ```bash
   git add .
   git commit -m "Add your feature"
   ```
4. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```
5. **Open a Pull Request** on GitHub

### Pull Request Guidelines

- **Title:** Use a clear, descriptive title
- **Description:** Explain what your PR does and why it's needed
- **Tests:** Include tests for new functionality
- **Documentation:** Update documentation if needed
- **Changelog:** If this is a significant change, consider updating the changelog

### Review Process

1. Your PR will be reviewed by maintainers
2. You may be asked to make changes
3. Once approved, your PR will be merged

## Security Issues

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for reporting instructions.

## Reporting Issues

When reporting issues, please include:

- Python version
- Operating system
- Advocate version
- requests and urllib3 versions
- Steps to reproduce the issue
- Expected vs actual behavior

## Project Structure

```
Advocate/
├── advocate/           # Main package
│   ├── __init__.py     # Package exports
│   ├── api.py          # Main API functions and classes
│   ├── addrvalidator.py # Address validation logic
│   ├── adapters.py     # HTTP adapters with validation
│   ├── connection.py   # Connection handling with validation
│   ├── connectionpool.py # Connection pool classes
│   ├── poolmanager.py  # Pool manager with validation
│   ├── futures.py      # Async support
│   └── exceptions.py   # Custom exceptions
├── test/               # Tests
├── examples/           # Example code
├── pyproject.toml      # Project metadata and configuration
├── README.md           # Project documentation
└── .github/            # GitHub configuration
    └── workflows/       # CI/CD workflows
```

## Code Guidelines

### Type Hints

Use Python type hints where possible. They help with:
- Code clarity
- Static analysis
- IDE support

### Documentation

- Use docstrings following Google style
- Document all public functions and classes
- Include examples where helpful

### Backwards Compatibility

- Be mindful of breaking changes
- Deprecate features gradually when needed
- Document breaking changes in the changelog

### Security Considerations

When contributing security-related code:
- Think about edge cases
- Consider how the change affects the overall security model
- Test with various network configurations
- Consider IPv4, IPv6, and tunneling protocols

## License

By contributing to Advocate, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
