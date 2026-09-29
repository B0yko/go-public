# Contributing

Thanks for looking at `go-public`. Bug reports, false positives, false negatives and pull requests are welcome. For a missed or wrongly reported finding use the issue forms, and never paste a real secret or real personal data into an issue: a made-up value of the same shape is enough (see [SECURITY.md](SECURITY.md)).

## Development setup

You need `git` 2.44 or newer and [uv](https://docs.astral.sh/uv/). uv installs Python 3.12 itself.

```sh
git clone https://github.com/B0yko/go-public
cd go-public
uv sync
uv run go-public --version
uv run go-public demo
```

## Tests, lint, types

Every commit should leave these green. CI runs them on Linux and macOS.

```sh
uv run pytest                     # unit and integration tests
uv run pytest tests/unit          # the quick loop
uv run ruff check
uv run ruff format --check        # `uv run ruff format` fixes formatting
uv run mypy src
uv run python scripts/sync_readme.py --check
```

The tests use no network. They run with an isolated `HOME` and without any `GIT_*` variable of yours, so your git config cannot change a result. Tests may build scenario repositories with plain `subprocess` calls to git; the package itself reaches git only through `go_public.git.runner`, which has an allowlist of subcommands per role (the one exception is the git-filter-repo child process of `export --keep-history`, which works on a fresh clone and never on the source). The source repository is read-only by construction, and a test asserts that nothing in the package calls `git push`.

`README.md` carries generated blocks (the configuration table and every results table). Do not edit them by hand: `uv run python scripts/sync_readme.py` rewrites them from `bench/results/` and the config model, and a test fails when they differ.

## Plant-shaped strings are assembled at run time

`go-public` finds secrets, emails, phone numbers, private addresses, user paths and internal hostnames, and it scans its own repository in CI. So no committed file may contain a string that it would flag at medium severity or above: not in tests, not in the fixture generator, not in the docs.

- Build such strings from parts when a test or the fixture generator needs one: a provider's documented prefix plus characters from a seeded random generator, `"10." + "0.3.7"`, `"/Us" + "ers/" + name + "/"`, and so on. `tests/unit/secret_tokens.py` has helpers for tokens.
- Use only placeholders in the docs: `/Users/<user>/`, addresses reserved for documentation (RFC 5737 and RFC 3849), `.example` and `example.com` domains. Name the private ranges by RFC number (RFC 1918, RFC 6598, RFC 3927, RFC 4193), not as CIDR literals, and do not write hosts under an internal suffix such as `.internal` or `.local`.
- Trailer names such as `Co-authored-by` may appear in config values and docs, but no commit message may carry a trailer with a name or email.
- Only `src/go_public/detect/constants.py` (the private ranges and path prefixes the detectors compare against) and `src/go_public/rules/gitleaks.toml` (the vendored rule set) are allowlisted, in the committed `.go-public.toml`, each with a reason. Do not add entries to make a test pass; assemble the string at run time instead.

The self-scan runs `go-public scan . --include-unreachable --fail-on medium`. Run it yourself before you open a pull request. It also reads the identities of your own commits, so it reports them unless they are on the allowlist; add `--head-only` to check the files alone:

```sh
uv run go-public scan . --include-unreachable --fail-on medium
```

The committed config allows the maintainer's public identity and no other. On a pull request CI scans only the tree it checks out, the merge of your branch into its base (`--head-only`), because your own commit identities are identity findings by definition. Use a GitHub noreply address for your commits if you do not want your email address in a public history, and make commits with `TZ=UTC git commit` if you want timezone offsets out of it (they are reported at info level).

## Changing a detector

Detector behaviour is measured on synthetic repositories, and the measurements only mean something if the process is honest:

- **Tune on seeds 0 and 1 only.** These are the tuning seeds for thresholds, patterns and hard negatives: `go-public bench --seeds 0,1 --size small`.
- **Seeds 2 to 6 are held out.** Run `go-public bench --seeds 2-6 --size small` after the detector code is frozen, once. Do not change code in response to a held-out result. If you must, re-run on fresh seeds (7 to 11) and report both runs.
- The CI smoke uses seeds 0 and 1 on the `tiny` size (`go-public bench --seeds 0,1 --size tiny --gate`).
- A fix for a false positive or a false negative comes with a test whose strings are assembled at run time, and, for a false positive, a hard negative in the fixture generator when the pattern is general.
- The fixture generator and the detectors share an author, so synthetic scores are an upper bound. Real-world noise (`bench --real-world-dir`) and the gitleaks baseline (`bench --gitleaks`) exist to check that.
- Heavy runs (`small` and `medium` sweeps, real-world clones, runtime measurements) belong on a machine that is otherwise idle. Results files record the hardware, the date, the git and go-public versions and the frozen detector commit. Never type a number into the README; regenerate the results file and sync.

Architecture decisions are recorded as short notes in `docs/adr/` (context, decision, consequences). Add one when a change makes a decision that is not obvious from the code.

## Pull requests

- Keep a change small and focused, with tests. Use [conventional commit](https://www.conventionalcommits.org/) messages (`fix(pii): ...`, `feat(export): ...`).
- Do not add `Signed-off-by` or `Co-authored-by` trailers with a name or email: the tool's own self-scan reports them (as trailer findings at medium severity).
- Everything in the repository is in English.
- Keep plans and scratch notes out of the repository.

By contributing you agree that your contribution is licensed under the Apache License 2.0, like the rest of the project.
