# Contributing Guidelines

Thank you for your interest in contributing!

# 1. How to Contribute

## Reporting Issues
- Provide clear reproduction steps.
- Include logs or screenshots when possible.

## Submitting Pull Requests
- Keep PRs focused and modular.
- Update tests when applicable.
- Provide a clear explanation of changes.

---

# 2. Branch Strategy

We follow a structured branching model to ensure stability and parallel development.

## Branch Naming Convention
- **`main`**: Production-ready code. Do not push directly to main.
- **`feature/feature-name`**: For new features (e.g., `feature/login-screen`).
- **`bugfix/issue-description`**: For non-critical bug fixes (e.g., `bugfix/fix-typo`).
- **`hotfix/critical-issue`**: For critical production fixes (e.g., `hotfix/crash-on-launch`).

## Commit Convention
We use **Gitmoji** style for commit messages.
Format: `[Gitmoji] [description]`

Examples:
- ✨ add login flow
- 🐛 handle null token
- 📝 update readme
- ♻️ clean up auth logic
- ✅ add unit tests
- 🔧 update dependencies

---

# 3. Coding Standards
- Follow Dart & Flutter best practices.
- Write clean, maintainable code.
- Add comments for complex logic.

---

# 4. Third-Party Package Usage Guidelines

## Licensing & Compliance
- Ensure licenses are compatible with the MIT license.
- Document licenses in `pubspec.yaml`.

## Security & Maintenance
- Prefer well-maintained packages.
- Check for vulnerabilities using `flutter pub outdated`.
- Minimize unnecessary dependencies.

## Proper Attribution
- Credit package authors when heavily influencing implementation.
- Report issues responsibly to maintainers.

## Behavioral Expectations
- Be respectful to third-party maintainers.
- Avoid misuse (rate limit abuse, etc.)
- Test integrations thoroughly.

---

# 5. Running the Project

```bash
flutter pub get
flutter run
```

---

# 6. Code of Conduct

By contributing, you agree to follow our CODE_OF_CONDUCT.md.