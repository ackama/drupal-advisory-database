import typing


class EntityReferenceField(typing.TypedDict):
  resource: typing.Literal['node', 'comment']
  uri: str
  id: str


class RichTextField(typing.TypedDict):
  format: typing.Literal['1']
  value: str


class Node(typing.TypedDict):
  nid: str
  type: str


class Advisory(Node):
  field_is_psa: typing.Literal['0', '1']
  field_affected_versions: str | None
  field_project: EntityReferenceField
  field_fixed_in: list[EntityReferenceField]
  field_sa_reported_by: RichTextField
  field_sa_criticality: str
  field_sa_cve: list[str]
  field_sa_description: RichTextField
  created: str
  changed: str
  title: str
  url: str


class ProjectModule(Node):
  field_project_machine_name: str


class ProjectRelease(Node):
  field_release_version: str
  field_release_version_major: str
  field_release_version_minor: str
  field_release_version_patch: str


TNode = typing.TypeVar('TNode', bound=Node)


class ApiResponse(typing.TypedDict, typing.Generic[TNode]):
  self: str
  first: str
  last: str
  next: str
  list: list[TNode]
