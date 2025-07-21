# https://packages.drupal.org/8/security-advisories/?updatedSince=0

import typing


class Source(typing.TypedDict):
  name: str
  remoteId: str


class Advisory(typing.TypedDict):
  advisoryId: str
  packageName: str
  title: str
  link: str
  cve: str
  affectedVersions: str
  sources: list[Source]
  reportedAt: str
  composerRepository: str
  severity: str | None


class SecurityAdvisoriesResponse(typing.TypedDict):
  advisories: dict[str, list[Advisory]] | list[typing.Never]
