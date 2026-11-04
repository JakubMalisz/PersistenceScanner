# Contributing to PersistenceScanner

First off, thank you for considering contributing to PersistenceScanner! It's people like you that make open-source security tools better, faster, and more effective for everyone.

This document outlines the process for contributing to the project, understanding the architecture, maintaining code quality, and adding new detection modules or threat intelligence.

---

## How Can I Contribute?

There are several ways you can help improve this project:

* **Reporting Bugs:** Open an issue if you find a false positive, a crash, or a logic flaw. Please include details about your OS, Go version, and the specific file or rule that caused the issue.
* **Suggesting Enhancements:** Have an idea for a new detection vector or a better regex pattern? Open an issue to discuss it before submitting a Pull Request.
* **Adding Threat Intelligence:** You can contribute to the core threat feed by submitting PRs to update the `rules.json` file with new evasion techniques or malicious indicators.
* **Writing Code:** The most impactful way to contribute is by adding new analysis modules (Analyzers) to cover more Linux persistence mechanisms.

---

## Development Setup

1. Make sure you have [Go](https://golang.org/doc/install) installed (version 1.20+ is recommended).
2. Clone the repository:
   ```bash
   git clone https://github.com/JakubMalisz/PersistenceScanner.git
   cd PersistenceScanner
   ```
3. Build the project to verify everything works:
   ```bash
   go build -o pscanner main.go
   ```

---

## Architecture Overview

PersistenceScanner relies on a decoupled, modular architecture designed for performance and extensibility.

* **Core Engine (`main.go`, `internal/scanner`):** Handles the CLI, concurrent directory scanning using goroutines/channels, and fetching rules (`internal/feed`).
* **Analyzers (`cron/`, `pam/`, `systemd/`, `udev/`, etc.):** Independent modules that implement the `Analyzer` interface.
* **Rules Engine (`rules.json`):** Threat intelligence is fully separated into a remote JSON file, evaluated using Go's `regexp` package.

---

## Adding a New Module

To add a new persistence detection vector (e.g., SSH configurations, bash profiles, X11 auto-start), follow these steps:

### 1. Implement the `Analyzer` Interface
Create a new directory in the project for your module (e.g., `ssh/`). Your main analyzer file (`analyzer.go`) must implement the following interface:
```go
type Analyzer interface {
    GetPaths() []string
    Analyze(file *core.FileData) ([]core.Alert, error)
}
```

### 2. Create a Parser (`parser.go`)
Your module should have a dedicated parser to handle I/O, format validation, and macro/variable expansion if necessary.
* **Filtering:** The parser must filter out irrelevant file extensions immediately.
* **Nil-Safety:** If a file is skipped or invalid, return an empty struct (e.g., `&MyModuleSpecs{}`) rather than `nil` to prevent nil pointer dereferences in the Analyzer. 
* **Payload Integrity:** Do not alter the raw payloads/commands if possible; let the central regex engine handle the matching.

### 3. Update the Registry
Register your new module in the central orchestrator (`main.go`) inside the module selection logic so it becomes available in the CLI menu.

---

## Updating Threat Intelligence (`rules.json`)

When adding new regex patterns to `rules.json`, please adhere to the following structure and best practices:

### 1. JSON Schema
Each rule must contain three fields:
```json
{
  "indicator": "regex_pattern_here",
  "description": "Clear explanation of the malicious behavior.",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL"
}
```

### 2. Regex Best Practices
* **Avoid False Positives:** Use word boundaries (`\b`) when targeting short commands (e.g., `\bod\s+-` instead of `od\s+-`) to prevent matching substrings in valid configuration files.
* **Escape Properly:** Remember that JSON requires double escaping for regex backslashes (e.g., `\\s+` for a whitespace, `\\\\` for a literal backslash).
* **Severity Context:** Use `MEDIUM` for evasion techniques or built-in macro substitutions (like `$env{}` in Udev) that could be used legitimately. Reserve `HIGH` and `CRITICAL` for explicit indicators of compromise (e.g., Reverse Shells, `LD_PRELOAD`).

---

## Coding Standards & Testing

To ensure the codebase remains clean and maintainable:

* **Idiomatic Go:** Follow standard Go formatting. Run `go fmt ./...` before committing your code.
* **Error Handling:** Do not ignore errors. Avoid using `panic` inside analyzers or parsers; always return the error to the core orchestrator.
* **Testing:** If you add a new parser, write a short unit test (`parser_test.go`) containing mock configuration files (both clean and malicious). 
* **Run Tests:** Ensure all tests pass by running `go test ./...`.

---

## Pull Request Process

1. Fork the repository and create your branch from `main` (e.g., `feature/ssh-module` or `fix/regex-false-positive`).
2. Ensure your code follows the coding standards and tests pass.
3. If you added a new module, update the `README.md` to reflect the new feature in the "Built-in Analysis Modules" list.
4. Issue that Pull Request! Please include a clear description of the problem you are solving and screenshots if you are adding a new feature.
5. A maintainer will review your code, discuss potential improvements, and merge it.

---
