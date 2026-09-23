const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const RESOURCE_INDEX = /at index (\d+)/g;
const PRECONDITION_VERSIONS =
  /the stored version \(\d+\) does not match the required base version \(\d+\)/g;

function normalizeString(value, { project, recordProject, key, scope }) {
  const projectPrefix = `projects/${project}/`;
  if (scope === "error" && project !== recordProject && value.includes(projectPrefix)) {
    const difference = project.length - recordProject.length;
    value = value.replace(RESOURCE_INDEX, (match, index) =>
      Number(index) >= `projects/${project}`.length
        ? `at index ${Number(index) - difference}`
        : match,
    );
  }
  value = value.replaceAll(project, recordProject);
  if (scope === "error") {
    value = value.replace(
      PRECONDITION_VERSIONS,
      "the stored version (<version>) does not match the required base version (<version>)",
    );
  }
  if (INSTANT.test(value) && Number(value.slice(0, 4)) >= 2026) return "<now>";
  if (key === "transaction") return "<txn>";
  if (key === "nextPageToken") return "<token>";
  if (key === "name") return value.replace(/\/[A-Za-z0-9]{20}$/, "/<auto-id>");
  return value;
}

/** Normalize only known recording noise; preserve status, code, shape, and array order. */
export function normalizeRecordedResponse(value, options, key = "") {
  const { project, recordProject, scope } = options;
  if (
    !project ||
    !recordProject ||
    typeof project !== "string" ||
    typeof recordProject !== "string"
  ) {
    throw new Error("recording project identities are required");
  }
  if (typeof value === "string") {
    return normalizeString(value, { project, recordProject, key, scope });
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeRecordedResponse(item, options, key));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((member) => [
          member,
          scope === "database-metadata" && ["etag", "uid"].includes(member)
            ? `<database-${member}>`
            : normalizeRecordedResponse(value[member], options, member),
        ]),
    );
  }
  return value;
}
