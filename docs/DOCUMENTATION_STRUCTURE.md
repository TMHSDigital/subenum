# Project Documentation Structure

This document outlines a recommended structure for comprehensive project documentation. While tailored for a Go-based CLI tool like `subenum`, the principles are broadly applicable.

## 1. Core Documentation (`README.md`)

This is the gateway to your project. It should be concise, informative, and guide users to other relevant documentation.

*   **Project Title & Tagline:** Clear and descriptive.
*   **Badges (Optional but Recommended):**
    *   Build status (e.g., GitHub Actions)
    *   Code coverage
    *   Go Report Card
    *   License
    *   Version/Release
*   **Brief Description:** What the project does in a few sentences.
*   **Cybersecurity Context / Educational Goals (If applicable):** Why this tool/project is important, especially from a learning or security perspective.
*   **Features:** Bulleted list of key capabilities.
*   **Prerequisites:** What users need to have installed/configured.
*   **Installation / Setup:**
    *   From source (e.g., `go build`, `go install`)
    *   Pre-compiled binaries (if provided)
    *   Docker (if applicable)
*   **Usage:**
    *   Basic command-line syntax.
    *   Explanation of all flags and arguments.
    *   Clear examples of common use cases.
*   **Output Explanation:** Describe what the output means.
*   **Contributing:** Guidelines for developers who want to contribute (link to `CONTRIBUTING.md`).
*   **License:** Link to `LICENSE.md`.
*   **Contact / Support (Optional):** How to get help or report issues.

## 2. Architecture Documentation (`ARCHITECTURE.md` or `/docs/architecture.md`)

This describes the "how" of your project. It's crucial for maintainers and contributors.

*   **Overview:** High-level diagram and explanation of the system's components and their interactions.
*   **Key Components / Modules:**
    *   For each major component (e.g., in `subenum`: argument parsing, wordlist processing, DNS resolution, concurrency management, output formatting):
        *   Purpose and responsibilities.
        *   Key functions/structs.
        *   Interactions with other components.
*   **Data Flow:** How data moves through the system (e.g., from wordlist to DNS resolver to output).
*   **Concurrency Model (If applicable):**
    *   Explanation of how concurrency is achieved (e.g., goroutines, channels, worker pools).
    *   Rationale for design choices.
    *   Potential bottlenecks or considerations.
*   **Error Handling Strategy:** How errors are propagated, logged, and handled.
*   **External Dependencies:** List of external libraries and why they were chosen.
*   **Design Decisions & Rationale:** Important architectural choices made and the reasons behind them. This can include alternatives considered and why they were not chosen.
*   **Future Considerations / Potential Improvements:** Areas for future development or refactoring.

## 3. Developer Guide (`DEVELOPER_GUIDE.md` or `/docs/developer_guide.md`)

Information for those who want to build, test, or contribute to the project.

*   **Getting Started:**
    *   Cloning the repository.
    *   Setting up the development environment (Go version, tools, environment variables).
    *   Building the project from source.
*   **Running Tests:**
    *   How to execute unit tests, integration tests, etc.
    *   Test coverage tools.
*   **Coding Style / Conventions:** Link to any style guides or linters used.
*   **Debugging Tips:** Common issues and how to troubleshoot them.
*   **Making Changes:**
    *   Branching strategy.
    *   Commit message conventions.
    *   Pull Request process.
*   **Dependencies Management:** How to add or update dependencies (e.g., `go get`, `go mod tidy`).

## 4. Contribution Guidelines (`CONTRIBUTING.md`)

How others can contribute to the project.

*   **Code of Conduct:** Link to `CODE_OF_CONDUCT.md`.
*   **How to Contribute:**
    *   Reporting bugs (issue tracker, templates).
    *   Suggesting enhancements.
    *   Submitting pull requests.
*   **What to Work On:** (Optional) Links to "good first issues" or a project board.

## 5. Code of Conduct (`CODE_OF_CONDUCT.md`)

Sets expectations for community interaction. Adopt a standard one like the Contributor Covenant.

## 6. License (`LICENSE` or `LICENSE.md`)

Specifies how the software can be used, modified, and distributed (e.g., MIT, Apache 2.0, GPL).

## 7. Changelog (`logs/CHANGELOG.md`)

A chronological list of notable changes for each version/release.

*   Follows Keep a Changelog format (Added, Changed, Deprecated, Removed, Fixed, Security).

## 8. Examples (`/examples` directory)

*   Provide more extensive or varied examples of how to use the tool.
*   Sample wordlists, configuration files, or scripts.

## 9. API Documentation (If applicable - for libraries or tools with an API)

*   For Go projects, this is often generated using `godoc`.
*   Ensure public functions and types are well-commented.

## 10. `/docs` Directory (Optional - for larger projects)

For more complex projects, you might move `ARCHITECTURE.md`, `DEVELOPER_GUIDE.md`, and other detailed documents into a dedicated `/docs` directory to keep the root directory cleaner.

---

This structure provides a solid foundation. Adapt it to the specific needs and complexity of your project. 