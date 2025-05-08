# Contributing to subenum

We welcome contributions! Please read this guide to understand how you can contribute.

*Refer to `CODE_OF_CONDUCT.md`.*

## Development Environment Setup

### Prerequisites

- Go 1.22 or later
- Git
- Make (optional but recommended)
- Docker (optional, for containerized development)

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/subenum.git
   cd subenum
   ```
3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/original-owner/subenum.git
   ```

## Development Workflow

### Using Make

The project includes a Makefile to simplify development tasks:

```bash
# Build the binary
make build

# Run tests
make test

# Run linter
make lint

# Clean up build artifacts
make clean

# Run the tool with default parameters
make run
```

### Using Docker

You can use Docker for development to ensure a consistent environment:

```bash
# Build the Docker image
make docker-build

# Run the tool in a Docker container
make docker-run
```

## Pull Request Process

1. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure they follow the project's coding standards

3. **Test your changes**:
   ```bash
   make test
   make lint
   ```

4. **Commit your changes** with a clear message describing the change

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a pull request** to the main repository

7. **Address any feedback** from the code review

## Ethical Guidelines

Please ensure that any contributions adhere to the ethical usage principles of this project:

- Features should be designed for educational or legitimate security testing purposes
- Consider potential misuse and implement appropriate safeguards
- Document proper usage scenarios and any necessary warnings

## *(Details on reporting bugs, suggesting features, pull requests.)* 