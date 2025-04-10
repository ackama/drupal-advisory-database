import typing

EcosystemType = typing.Literal[
  'AlmaLinux',
  'Alpine',
  'Android',
  'Bioconductor',
  'Bitnami',
  'Chainguard',
  'ConanCenter',
  'CRAN',
  'crates.io',
  'Debian',
  'GHC',
  'GitHub Actions',
  'Go',
  'Hackage',
  'Hex',
  'Kubernetes',
  'Linux',
  'Mageia',
  'Maven',
  'npm',
  'NuGet',
  'openSUSE',
  'OSS-Fuzz',
  'Packagist',
  'Photon OS',
  'Pub',
  'PyPI',
  'Red Hat',
  'Rocky Linux',
  'RubyGems',
  'SUSE',
  'SwiftURL',
  'Ubuntu',
  'Wolfi',
]


class Package(typing.TypedDict):
  """
  Package describes the affected code library or command provided by the package.

  See: https://ossf.github.io/osv-schema/#affectedpackage-field
  """

  ecosystem: str
  name: str
  purl: typing.NotRequired[str]


class Event(typing.TypedDict, total=False):
  """
  Event describes a single version that either:
    - Introduces a vulnerability: {"introduced": string}
    - Fixes a vulnerability: {"fixed": string}
    - Describes the last known affected version: {"last_affected": string}
    - Sets an upper limit on the range being described: {"limit": string}

  Event instances form part of a "timeline" of status changes for the affected
  package described by the affected class.

  See: https://ossf.github.io/osv-schema/#affectedrangesevents-fields
  """

  introduced: str
  fixed: str
  last_affected: str
  limit: str


RangeType = typing.Literal[
  'SEMVER',
  'ECOSYSTEM',
  'GIT',
]


class Range(typing.TypedDict):
  """
  Range describes the affected range of given version for a specific package.

  See: https://ossf.github.io/osv-schema/#affectedranges-field
  """

  type: RangeType
  events: list[Event]
  repo: typing.NotRequired[str]
  database_specific: typing.NotRequired[dict[str]]


SeverityType = typing.Literal[
  'CVSS_V2',
  'CVSS_V3',
  'CVSS_V4',
]


class Severity(typing.TypedDict):
  """
  Severity describes the severity of a vulnerability for an affected package
  using one or more quantitative scoring methods.

  See: https://ossf.github.io/osv-schema/#severity-field
  """

  type: SeverityType
  score: str


class Affected(typing.TypedDict, total=False):
  """
  Affected describes an affected package version, meaning one instance that
  contains the vulnerability.

  See: https://ossf.github.io/osv-schema/#affected-fields
  """

  package: Package
  severity: list[Severity]
  ranges: list[Range]
  versions: list[str]
  database_specific: dict[str]
  ecosystem_specific: dict[str]


ReferenceType = typing.Literal[
  'ADVISORY',
  'ARTICLE',
  'DETECTION',
  'DISCUSSION',
  'REPORT',
  'FIX',
  'INTRODUCED',
  'GIT',
  'PACKAGE',
  'EVIDENCE',
  'WEB',
]


class Reference(typing.TypedDict):
  """
  Reference links to additional information, advisories, issue tracker entries,
  and so on about the vulnerability itself.

  See: https://ossf.github.io/osv-schema/#references-field
  """

  type: ReferenceType
  url: str


CreditType = typing.Literal[
  'FINDER',
  'REPORTER',
  'ANALYST',
  'COORDINATOR',
  'REMEDIATION_DEVELOPER',
  'REMEDIATION_REVIEWER',
  'REMEDIATION_VERIFIER',
  'TOOL',
  'SPONSOR',
  'OTHER',
]


class Credit(typing.TypedDict):
  """
  Credit describes who to give credit to for the discovery, confirmation, patch,
  or other events in the life cycle of a vulnerability.

  See: https://ossf.github.io/osv-schema/#credits-fields
  """

  name: str
  type: typing.NotRequired[CreditType]
  contact: typing.NotRequired[list[str]]


class Vulnerability(typing.TypedDict, total=False):
  """
  Vulnerability is the core Open Source Vulnerability (OSV) data type.

  The full documentation for the schema is available at
  https://ossf.github.io/osv-schema.
  """

  schema_version: str
  id: typing.Required[str]
  modified: typing.Required[str]
  published: str
  withdrawn: str
  aliases: list[str]
  related: list[str]
  upstream: list[str]
  summary: str
  details: str
  severity: list[Severity]
  affected: list[Affected]
  references: list[Reference]
  credits: list[Credit]
  database_specific: dict[str]
