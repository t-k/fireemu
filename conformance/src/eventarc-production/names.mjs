// Channel names of a production recording. Every channel the recorder creates carries the run's prefix,
// so that it can be found and removed by prefix and nothing else can be changed. The few IDs that are
// refused on purpose (upper case, too short, `goog...`) cannot carry the prefix; they are registered as
// probes before they are sent, so that one that is accepted by mistake is still known and removed.

import { prefixOf } from "../pubsub-production/names.mjs";

const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const LOCATION = /^[a-z][a-z0-9-]{1,40}$/;

export { isRunId, newRunId } from "../pubsub-production/names.mjs";

export function createOwnership({ project, runId }) {
  if (typeof project !== "string" || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project))
    throw new Error("the project is not a project ID");
  const prefix = prefixOf(runId);
  const base = `projects/${escaped(project)}/locations/`;
  const pattern = new RegExp(`^${base}[a-z][a-z0-9-]{1,40}/channels/${escaped(prefix)}[a-z0-9-]*$`);
  const probePattern = new RegExp(`^${base}[a-z][a-z0-9-]{1,40}/channels/[^/]+$`);
  const probes = new Set();
  const issued = new Set();
  const publishTargets = new Set();
  const locations = new Set();
  return Object.freeze({
    project,
    runId,
    prefix,
    /** The name of an owned channel in `location`. */
    channel: (location, key) => {
      if (!LOCATION.test(location)) throw new Error("not a location");
      const id = `${prefix}${key}`;
      if (!/^[a-z][a-z0-9-]*$/.test(id) || id.length > 63)
        throw new Error("not a usable channel ID");
      const name = `projects/${project}/locations/${location}/channels/${id}`;
      issued.add(name);
      locations.add(location);
      return name;
    },
    /**
     * A name sent on purpose that cannot carry the prefix. `listable` is false for a name in a location
     * that cannot exist, whose list would only be an error.
     */
    registerProbe: (name, { listable = true } = {}) => {
      if (typeof name !== "string" || !probePattern.test(name))
        throw new Error("a probe must name one channel of the project");
      probes.add(name);
      if (listable) locations.add(name.split("/")[3]);
      return name;
    },
    /**
     * A channel the run may publish to although it is not the run's (the default channel, once it was read
     * as absent). It is never a probe: the cleanup does not touch it, whatever a list shows.
     */
    allowPublish: (name) => {
      if (typeof name !== "string" || !probePattern.test(name))
        throw new Error("a publish target must name one channel of the project");
      publishTargets.add(name);
      return name;
    },
    assertPublishable: (name) => {
      if (
        typeof name !== "string" ||
        !(pattern.test(name) || probes.has(name) || publishTargets.has(name))
      )
        throw new Error(`refusing to publish to ${String(name)}: it is not a channel of this run`);
      return name;
    },
    probes: () => [...probes],
    issued: () => [...issued],
    /** Every location the run named: the cleanup lists each of them. */
    locations: () => [...locations].toSorted(),
    isOwned: (name) => typeof name === "string" && (pattern.test(name) || probes.has(name)),
    assertOwned: (name) => {
      if (typeof name !== "string" || !(pattern.test(name) || probes.has(name)))
        throw new Error(`refusing to change ${String(name)}: it is not a channel of this run`);
      return name;
    },
    prefixPattern: pattern,
  });
}
