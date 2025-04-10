import typing


class SANodeField(typing.TypedDict):
  resource: typing.Literal['node', 'comment']
  uri: str
  id: str


class SARichTextField(typing.TypedDict):
  format: typing.Literal['1']
  value: str


class SAAdvisory(typing.TypedDict):
  field_is_psa: typing.Literal['0', '1']
  field_affected_versions: str | None
  field_project: SANodeField
  field_fixed_in: list[SANodeField]
  field_sa_reported_by: SARichTextField
  field_sa_criticality: str
  field_sa_cve: list[str]
  field_sa_description: SARichTextField
  created: str
  changed: str
  title: str
  url: str


class DrupalNode(typing.TypedDict):
  id: str


class DrupalProjectModule(DrupalNode):
  field_project_machine_name: str


class DrupalProjectRelease(DrupalNode):
  field_release_version: str
  field_release_version_major: str
  field_release_version_minor: str
  field_release_version_patch: str


TNode = typing.TypeVar('TNode', bound=DrupalNode)


class DrupalApiResponse(typing.TypedDict):
  list: list[TNode]
