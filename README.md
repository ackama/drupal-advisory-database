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

This repo ships with a `.osv-detector.yml` file.  From this repo you can check your project with `osv-detector -config .osv-detector.yml /path/to/your/repo`

## How it works

The script takes 2 approaches to finding Security Advisory nodes.

All results of API calls are saved locally for rapid prototyping and to not hammer the APIs.

### RSS

The obvious source is the RSS feeds of the [core](https://www.drupal.org/security/core)
and [contrib](https://www.drupal.org/security/contrib) feeds hosted on Drupal.org

### CVEs

> This is currently a WIP and commented out.

The other source that has a longer history, but only includes SAs that had a matching CVE created.

This process will checkout the full CVE repo and try to pull out a Security Advisory node from any of the URLs found.

### Building the OSV file

This process starts from the Security Advisory node. From this we can get the Project node and any Release nodes.

We are using the [api-d7](https://www.drupal.org/drupalorg/docs/apis/rest-and-other-apis#s-restful-web-services) which is provided by the [RESTful Web Services](https://www.drupal.org/project/restws) module. This allows us to fetch the nodes as JSON.

From the 3 types of nodes we have all we need to build the OSV file.

## Validating files

Fetch the current `schema.json` file from the [Open Source Vulnerability schema](https://ossf.github.io/osv-schema/#format-overview) repo and save it into the project root dir.

The following will validate all generated files.

```shell
for F in $(ls osv/*.json); do go run github.com/neilpa/yajsv@latest -s schema.json $F
; done
```

## TODO

OSV Detector does not like the affected ranges events being out of order.  Manual testing showed that the `fixed` version had to follow the `introduced` version as the next entry. A collection of `introduced` couldn't be followed by a collection of `fixed` so this still needs some attention.  Once this is done though, I think this may be good to go.
