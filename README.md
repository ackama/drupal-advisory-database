# Drupal Advisory Database

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ackama/drupal-advisory-database/badge)](https://scorecard.dev/viewer/?uri=github.com/ackama/drupal-advisory-database)

A community-driven database of known security vulnerabilities in Drupal packages
sourced from [drupal.org](https://www.drupal.org/security) using the
[OSV](https://ossf.github.io/osv-schema/) format.

The data is primarily sourced using the drupal.org
[REST API](https://www.drupal.org/drupalorg/docs/apis/rest-and-other-apis).

## Using this database

This database can be used by any tool that supports ingesting OSV advisories.

If you are using [`osv-detector`](https://github.com/G-Rath/osv-detector), you
can configure this database as an
[extra database](https://github.com/G-Rath/osv-detector?tab=readme-ov-file#extra-databases)

## Updating the advisories

Advisories are managed through a series of Python scripts that live in the
`scripts` directory - to use these, you need to install the dependencies listed
in `pyproject.toml` using
[`poetry`](https://python-poetry.org/docs/#installation).

```shell
# 1. download the Drupal SA advisories from drupal.org
poetry run scripts/download_sa_advisories.py

# 2. download nodes from drupal.org related to the advisories
# (this is not required, but will significantly improve performance of the next step)
poetry run scripts/precache_nodes.py

# 3. generate the OSV advisories based on the Drupal advisories
poetry run scripts/generate_osv_advisories.py
```

## Fixing incorrect data

Sometimes an advisory will have incorrect data, such as an affected version
range which is syntactically or semantically incorrect; these can be temporarily
addressed by adding a "patch" for the impacted advisory to the
[`patches.toml`](./patches.toml) file in the root of this repository.

When patching an advisory, you need to provide a tuple assigned to the SA
advisory property whose value you wish to replace - the first element in the
tuple should be the current value, and the second element should be the
replacement value. The patch will only be applied if the current value matches
to ensure patches don't mistakenly undo upstream changes (which hopefully are
the result of the incorrect data being fixed!)

> [!NOTE]
>
> Currently, the patcher only supports the `field_affected_versions` property
> since that's the only property we've needed to patch; feel free to add support
> for additional properties when needed

The generator will mark advisories that have been patched to make it clear that
has happened; it will also attempt to identity some types of issues with the
data, which will be captured as `warnings`.
