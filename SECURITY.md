# Security policy

In short: report a vulnerability privately through GitHub, and report a missed finding in public with a made-up value of the same shape, never the real one.

## Supported versions

Security fixes go into the latest release, currently 0.1.x.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**, or go to <https://github.com/B0yko/go-public/security/advisories/new>. No email address is published for reports. Please do not open a public issue for a vulnerability.

What counts as a vulnerability in `go-public`:

- It prints or writes a secret in full when `--show-secrets` was not given (the report and the console show the first four characters, the length and a SHA-256 prefix).
- It changes the source repository, pushes, creates a remote, or makes a network connection. `scan`, `export`, `show`, `fixture` and `demo` never write to the source repository (objects, refs, config, index or working tree), and no command runs `git push`, `git fetch` or `git remote`. `strip` and `redact` edit only the files you name. All of them work offline by design; only `bench --real-world-dir` clones two public repositories.
- A crafted repository makes it run code: through a hook, `core.fsmonitor`, a filter or textconv driver, a transport, or a malformed file (image, PDF, OOXML, archive) it reads.
- The export writes outside the directory you gave it, or keeps content that its own re-scan should have caught in a way the documentation says it does not.
- A report is written somewhere readable by other users, or inside the scanned working tree.

Include the version (`go-public --version`), your platform and git version, and the smallest synthetic repository or command that shows the problem. Do not send a real secret, real personal data or a repository that contains them.

This is a one-person project. Reports are read as soon as possible, with no promised response time.

## Reporting a false negative

A missed finding is a bug in detection. It is not a vulnerability, so it does not need private reporting; use the public **False negative** issue form. Because the issue is public, **never paste the real value that was missed**. A synthetic reproduction is enough:

1. Take a value of the same shape as the real one: the same prefix, the same length and the same character set, with characters you made up.
2. Say where it sits: a file at HEAD, a deleted file, a side branch, a tag, a commit message, a file's metadata.
3. Better still, give a few `git` commands that build a tiny repository with the made-up value, and the command you ran.

If you cannot describe the miss without the real value, do not send it. Report the token format (the provider's documented prefix and length) instead. If a real credential was already pasted anywhere public, rotate it first; removing the comment does not un-leak it.

## What `go-public` does not cover

It is an aid to a review, not a guarantee. It does not scan issues, pull requests, wikis, release assets or Actions logs of an existing remote, files inside archives other than OOXML, text inside images, or encoded values. See the limitations section of the README. Publish the export as a new repository, and rotate every secret that was ever committed.
