# Sources

## CVEs

> This is currently a WIP and commented out.

The other source that has a longer history, but only includes SAs that had a
matching CVE created.

This process will checkout the full CVE repo and try to pull out a Security
Advisory node from any of the URLs found.

### Pros

- Well established dataset

### Cons

- Not simple to find the SA node
- Slow - These lag behind the SA releases
- Not all SAs get a CVE

## RSS

The obvious source is the RSS feeds of the
[core](https://www.drupal.org/security/core) and
[contrib](https://www.drupal.org/security/contrib) feeds hosted on Drupal.org

### Pros

- Easy to process

### Cons

- Limited to what ever is on that feed.
- Only has new SAs.
- No pagination

## RESTful Web Service API

### Pros

- All SA nodes are fetchable
- The feed can be sorted by given fields
- The direction of the sort can be specified
- Data is paginated
- Number of records can be specified

### Cons

- Maximum number of records per request is hardcoded at a maximum of 50
