# Contributing Guidelines

## Git Workflow

### Branch Naming Convention
- **Feature branches**: `feature/issue-number-short-description`
- **Bug fixes**: `fix/issue-number-short-description`
- **Documentation**: `docs/issue-number-short-description`
- **Refactoring**: `refactor/issue-number-short-description`

Examples:
- `feature/1-core-auth-handlers`
- `feature/4-jwt-utilities`
- `fix/12-email-validation-bug`
- `docs/13-api-documentation`

### Development Workflow

1. **Create a branch** from `main` for each issue:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/4-jwt-utilities
   ```

2. **Make your changes** following the coding standards

3. **Commit frequently** with descriptive messages (see commit format below)

4. **Push your branch** and create a Pull Request:
   ```bash
   git push origin feature/4-jwt-utilities
   gh pr create --title "feat: implement JWT utilities and password hashing" --body "Closes #4"
   ```

5. **Never push directly to main** - all changes must go through Pull Requests

6. **Delete feature branch** after merge:
   ```bash
   git branch -d feature/4-jwt-utilities
   ```

## Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation only changes
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvements
- **test**: Adding missing tests or correcting existing tests
- **chore**: Changes to build process or auxiliary tools

### Examples
```bash
feat(auth): add JWT token generation and validation

- Implement JWT token creation with configurable expiration
- Add token validation with proper error handling
- Include refresh token functionality
- Add comprehensive unit tests

Closes #4

fix(database): handle connection timeout gracefully

perf(cache): optimize Redis connection pooling

docs(readme): update installation instructions

test(auth): add integration tests for login flow

chore(deps): update dependencies to latest versions
```

### Commit Rules
- Use imperative mood ("add feature" not "added feature")
- Keep the first line under 72 characters
- Reference issue numbers in the footer with "Closes #N" or "Fixes #N"
- Include breaking changes in the footer with "BREAKING CHANGE:"

## Pull Request Guidelines

### PR Title Format
Use the same format as commit messages:
```
feat(auth): implement JWT utilities and password hashing
fix(database): resolve connection pool exhaustion
docs(api): add comprehensive endpoint documentation
```

### PR Description Template
```markdown
## Description
Brief description of the changes made.

## Related Issues
Closes #4
Related to #1

## Changes Made
- [ ] Added JWT token generation
- [ ] Implemented password hashing with bcrypt
- [ ] Added input validation utilities
- [ ] Created comprehensive unit tests

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Security builds compile successfully (see Security Build Testing below)

### Security Build Testing
Test all security build configurations to ensure compatibility:

```bash
# Test standard build (all databases)
cargo build
cargo test

# Test secure build (no MySQL RSA vulnerability)
cargo build --no-default-features --features secure
cargo test --no-default-features --features secure

# Test ultra-secure build (MongoDB only, maximum security)
cargo build --no-default-features --features ultra-secure
cargo test --no-default-features --features ultra-secure
```

All three builds must compile and pass tests for changes to be accepted.

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated as needed
- [ ] Documentation updated if required
- [ ] No breaking changes (or breaking changes documented)
```

### PR Review Process
1. **All PRs require review** before merging
2. **All checks must pass** (tests, linting, security scans)
3. **Resolve all conversations** before merging
4. **Squash and merge** to keep clean git history
5. **Delete feature branch** after merge

## Code Quality Standards

### Before Committing
```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run tests
cargo test

# Security audit
cargo audit
```

### Pre-commit Hooks (Recommended)
Install pre-commit hooks to automatically check code quality:

```bash
# Install pre-commit if not already installed
pip install pre-commit

# Set up hooks (create .pre-commit-config.yaml first)
pre-commit install
```

## Branch Protection Rules

The following rules should be enforced on the `main` branch:
- Require pull request reviews before merging
- Dismiss stale PR approvals when new commits are pushed
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Include administrators in restrictions

## Release Workflow

### Semantic Versioning
- **MAJOR**: Breaking changes (1.0.0 → 2.0.0)
- **MINOR**: New features, backward compatible (1.0.0 → 1.1.0)  
- **PATCH**: Bug fixes, backward compatible (1.0.0 → 1.0.1)

### Creating Releases
1. Ensure all features for the release are merged
2. Update version in `Cargo.toml`
3. Update `CHANGELOG.md`
4. Create release PR: `release/v1.0.0`
5. After merge, create and push git tag:
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```
6. GitHub Actions will automatically create the release

## Issue Workflow

1. **Assign yourself** to the issue before starting work
2. **Move issue to "In Progress"** in the project board
3. **Create feature branch** following naming convention
4. **Reference issue** in commits and PR
5. **Update issue** with progress and blockers
6. **Close issue** automatically with PR merge using "Closes #N"

## Code Review Guidelines

### For Authors
- Keep PRs focused and small (ideally <400 lines)
- Provide clear description and context
- Test your changes thoroughly
- Respond promptly to feedback
- Be open to suggestions and improvements

### For Reviewers
- Review code within 24 hours when possible
- Focus on correctness, security, and maintainability
- Provide constructive feedback
- Approve when code meets standards
- Check that tests are adequate

## Getting Help

- **Questions**: Open a discussion in the GitHub repository
- **Bugs**: Create an issue with detailed reproduction steps
- **Feature Requests**: Create an issue with clear requirements
- **Security Issues**: Email maintainers privately

## Quick Reference

### Common Git Commands
```bash
# Start working on an issue
git checkout main && git pull && git checkout -b feature/4-jwt-utilities

# Commit changes
git add . && git commit -m "feat(auth): implement JWT token validation"

# Push and create PR
git push origin feature/4-jwt-utilities
gh pr create --title "feat(auth): implement JWT utilities" --body "Closes #4"

# Clean up after merge
git checkout main && git pull && git branch -d feature/4-jwt-utilities
```

### Code Quality Check
```bash
cargo fmt && cargo clippy -- -D warnings && cargo test && cargo audit
```