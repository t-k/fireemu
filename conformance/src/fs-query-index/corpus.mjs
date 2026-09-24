// The FS-QUERY-INDEX corpus. Program ids are `fs-query-index/<area>/<case>`; the area is the
// closure condition that owns the program (spec/compatibility/closure/FS-QUERY-INDEX.json).

import { AGGREGATION_PROGRAMS } from "./programs/aggregation.mjs";
import { EXPLAIN_PROGRAMS } from "./programs/explain.mjs";
import { FILTER_PROGRAMS, LIMIT_PROGRAMS } from "./programs/filters.mjs";
import { GROUP_PROGRAMS } from "./programs/group.mjs";
import { GRPC_PROGRAMS } from "./programs/grpc.mjs";
import { INDEX_PROGRAMS } from "./programs/indexes.mjs";
import { ORDERING_PROGRAMS } from "./programs/ordering.mjs";
import { PARTITION_PROGRAMS } from "./programs/partition.mjs";
import { REQUEST_PROGRAMS } from "./programs/requests.mjs";
import { VECTOR_PROGRAMS } from "./programs/vector.mjs";

export const PROGRAMS = [
  ...FILTER_PROGRAMS,
  ...LIMIT_PROGRAMS,
  ...ORDERING_PROGRAMS,
  ...GROUP_PROGRAMS,
  ...AGGREGATION_PROGRAMS,
  ...VECTOR_PROGRAMS,
  ...PARTITION_PROGRAMS,
  ...EXPLAIN_PROGRAMS,
  ...INDEX_PROGRAMS,
  ...REQUEST_PROGRAMS,
  ...GRPC_PROGRAMS,
];
