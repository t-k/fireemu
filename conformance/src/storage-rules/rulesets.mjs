// Literal source declarations only. No compiler, publisher, or evaluator is invoked here.
export function renderRules(row, binding) {
  const { rule, casePrefix, objectName } = row;
  let match = `${casePrefix}{path=**}`;
  let grant = "read, write";
  let predicate;
  let allowLines;
  const literal = (value) => `'${value}'`;
  switch (rule.kind) {
    case "grant":
      grant = rule.grant;
      predicate = "true";
      break;
    case "deny":
      predicate = "false";
      break;
    case "anonymous":
      predicate = "request.auth == null";
      break;
    case "auth-required":
      grant = "get";
      predicate = "request.auth != null";
      break;
    case "uid":
      match = `${casePrefix}{owner}/{file=**}`;
      predicate = "request.auth != null && request.auth.uid == owner";
      break;
    case "claim":
      predicate = `request.auth != null && ${{ verified: "request.auth.token.email_verified == true", role: "request.auth.token.role == 'reader'", number: "request.auth.token.level == 7" }[rule.field]}`;
      break;
    case "stored-null":
      predicate = `resource ${rule.matches ? "==" : "!="} null`;
      break;
    case "state-dispatch": {
      if (!["create", "update"].includes(rule.permit)) throw new Error("unknown state grant");
      const other = rule.permit === "create" ? "update" : "create";
      allowLines = `allow ${rule.permit}: if true;\n      allow ${other}: if false;`;
      break;
    }
    case "delete-request-resource":
      if (typeof rule.matchesNull !== "boolean") throw new Error("invalid delete predicate");
      grant = "delete";
      predicate = `request.resource ${rule.matchesNull ? "==" : "!="} null`;
      break;
    case "time-window": {
      if (typeof rule.inside !== "boolean") throw new Error("invalid time predicate");
      grant = row.operation === "get-media" ? "get" : "create";
      const bounded =
        "request.time >= timestamp.date(2000, 1, 1) && request.time < timestamp.date(2100, 1, 1)";
      predicate = rule.inside ? bounded : `!(${bounded})`;
      break;
    }
    case "incoming":
    case "stored": {
      const incoming = rule.kind === "incoming";
      const resource = incoming ? "request.resource" : "resource";
      grant = incoming ? "update" : "get, update, delete";
      const values = {
        size: rule.matches ? "4" : "5",
        contentType: literal(
          rule.matches ? (incoming ? "text/markdown" : "text/plain") : "application/octet-stream",
        ),
        name: literal(rule.matches ? objectName : `${casePrefix}different.bin`),
        metadata: literal(rule.matches ? (incoming ? "new" : "old") : "different"),
      };
      const field = rule.field === "metadata" ? "metadata.owner" : rule.field;
      predicate = `${resource} != null && ${resource}.${field} == ${values[rule.field]}`;
      break;
    }
    case "upload-incoming": {
      grant = "create";
      if (rule.field === "metadata" && row.uploadProtocol === "simple") {
        predicate = `request.resource != null && ${rule.matches ? '!("owner" in request.resource.metadata)' : '"owner" in request.resource.metadata'}`;
        break;
      }
      const values = {
        size: rule.matches ? "4" : "5",
        contentType: rule.matches ? "'text/plain'" : "'application/octet-stream'",
        name: literal(rule.matches ? objectName : `${casePrefix}different.bin`),
        metadata: rule.matches ? "'probe'" : "'other'",
      };
      const field = rule.field === "metadata" ? "metadata.owner" : rule.field;
      predicate = `request.resource != null && request.resource.${field} == ${values[rule.field]}`;
      break;
    }
    case "bucket":
      predicate = `bucket == ${literal(rule.matches ? binding.bucket : `${binding.bucket}-other`)}`;
      break;
    case "leaf":
      match = `${casePrefix}{leaf}`;
      predicate = "leaf == 'allowed.bin'";
      break;
    case "recursive":
      match = `${casePrefix}anchor/{tail=**}`;
      predicate = "true";
      break;
    default:
      throw new Error("unknown rule declaration");
  }
  if (predicate?.includes("undefined")) throw new Error("unknown rule field");
  return `${rule.version === 2 ? "rules_version = '2';\n" : ""}service firebase.storage {\n  match /b/{bucket}/o {\n    match /${match} {\n      ${allowLines ?? `allow ${grant}: if ${predicate};`}\n    }\n  }\n}\n`;
}
