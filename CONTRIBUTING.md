# Setup

This codebase requires Python 3.13 and uses [Poetry](https://python-poetry.org/)
to manage dependencies.

# Testing

We use `pytest` for testing, which can be run with:

```shell
poetry run pytest
```

# Type checking

We use `mypy` to do strict type checking of Python scripts, which can be run
with:

```shell
poetry run mypy
```

# Linting

The primary linter for this codebase is `ruff`, which can be run with:

```shell
# lint everything possible
poetry run ruff check

# automatically apply fixes for linting errors
poetry run ruff check --fix
```

# Formatting

We use `ruff` to format Python files, which can be run with:

```shell
# format all supported files as needed
poetry run ruff check

# check if any files need formatting
poetry run ruff check --check
```

We use `prettier` to format other files, which can be run with:

```shell
# check everything possible for formatting issues
npx prettier --check .

# automatically format everything possible
npx prettier --write .

# format a subset of files
npx prettier path/to/my/file
```

> [!NOTE]
>
> You need to have Node installed to run `prettier`
