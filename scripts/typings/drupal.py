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


class AdvisoryBase(Node):
  field_is_psa: typing.Literal['0', '1']
  field_affected_versions: str | None
  field_fixed_in: list[EntityReferenceField]
  field_sa_criticality: str
  field_sa_cve: list[str]
  created: str
  changed: str
  title: str
  url: str


class Advisory(AdvisoryBase):
  """
  Represents an advisory sourced from the Drupal JSON API that has been
  transformed to make it easier to work with
  """

  field_project: EntityReferenceField | None
  field_sa_reported_by: RichTextField
  field_sa_description: RichTextField


class AdvisoryRaw(AdvisoryBase):
  """
  Represents an advisory provided by the Drupal JSON API without any post-processing.

  This mainly means that object fields which don't have a value in the database
  will be represented by an empty list due to how associated arrays in PHP work
  """

  field_project: EntityReferenceField | list[typing.Never]
  field_sa_reported_by: RichTextField | list[typing.Never]
  field_sa_description: RichTextField | list[typing.Never]


class Project(Node):
  # type will be project_module, project_theme, or project_core
  field_project_machine_name: str


class ProjectRelease(Node):
  field_release_version: str
  field_release_version_major: str
  field_release_version_minor: str
  field_release_version_patch: str


class ApiResponse[TNode: Node = Node](typing.TypedDict):
  self: str
  first: str
  last: str
  next: str
  list: list[TNode]
