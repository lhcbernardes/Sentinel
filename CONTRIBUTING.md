# Contributing to Sentinel-RS

Thank you for your interest in contributing!

## Code of Conduct

We are committed to providing a welcoming environment. Please read our full [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## How to Contribute

### Reporting Bugs

1. Check existing issues before creating a new one
2. Use bug report template
3. Include:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details

### Suggesting Features

1. Open an issue with `[Feature Request]` prefix
2. Describe the problem and proposed solution
3. Consider alternative approaches

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Follow our coding standards (run `cargo fmt` and `cargo clippy`)
4. Write tests for new functionality
5. Update documentation if needed
6. Submit PR with clear description

## Development Setup

```bash
# Clone repository
git clone https://github.com/sentinel-rs/sentinel-rs.git
cd sentinel-rs

# Install dependencies
cargo build

# Run tests
cargo test

# Run with formatting check
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo test
```

## Coding Standards

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Write unit tests for new code
- Document public APIs with doc comments
- Follow Rust naming conventions

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(devices): add OUI lookup cache

Improves device identification performance by caching OUI lookups.
Closes #123
```

## Review Process

1. All PRs require review
2. Address feedback promptly
3. Keep PRs focused and small

## Recognition

Contributors will be listed in README.md and CONTRIBUTORS.md.

## Questions?

- Open an issue for bugs/features
- Join our Discord (link in README)
- Email: hello@sentinel-rs.io