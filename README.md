# Drupal Advisory Database

This is an early attempt at getting Drupal Security Advisories into an OSV format for use with [OSV Detector](https://github.com/G-Rath/osv-detector)/[OSV Scanner](https://google.github.io/osv-scanner/).

## Usage

Check out the repo and run the script.

```shell
python ./drupal-sa-to-osv.py
```

The script will create all the necessary directories if they are not present.

## Usage in your project

### OSV Detector

[Install OSV Detector](https://github.com/G-Rath/osv-detector?tab=readme-ov-file#installation) and ensure it is on your `$PATH`.

This repo ships with an `.osv-detector.yml` file.  From this repo you can check your project with `osv-detector -config .osv-detector.yml /path/to/your/repo`

## How it works

A number of [SOURCES.md](SOURCES.md) were considered and are still present in the code.

The final one settled on was API provided by the [RESTful Web Services](https://www.drupal.org/project/restws) module.

This allows us to fetch a JSON feed of all the Security Advisory(SA) nodes, sorted by last modified so the first page is more than likely going to contain all the nodes we need to examine. The existing advisories are checked and the most recent changed date is used to decide if an SA should be fetched and processed or not and new SA's are processed. If we run out of nodes to process we stop there. If the full page has been processed then the next page is fetched for processing.

### Building the OSV file

This process starts from the Security Advisory node. From this we can get the Project node and any Release nodes.

We are using the [api-d7](https://www.drupal.org/drupalorg/docs/apis/rest-and-other-apis#s-restful-web-services) which is provided by the [RESTful Web Services](https://www.drupal.org/project/restws) module. This allows us to fetch the nodes as JSON.

From the 3 types of nodes we have all we need to build the OSV file.

## Validating files

Fetch the current `schema.json` file from the [Open Source Vulnerability schema](https://ossf.github.io/osv-schema/#format-overview) repo and save it into the project root dir.

The following will validate all generated files.

```shell
for F in advisories/*/*.json; do go run github.com/neilpa/yajsv@latest -s schema.json $F ; done
```


### Generating OSV advisories

First, (re)download the Drupal Security Advisories:

```shell
scripts/download_sa_advisories.py
```

This will download all SAs that have been modified since the most recent OSV modification time, and store them in `cache/advisories`.

Then, you can (re)generate the OSV advisories:

```shell
scripts/generate_osv_advisories.py
```
