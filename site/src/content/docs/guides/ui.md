---
title: Emulator UI
description: Inspect and manage data, Functions, Security Rules decisions and the clock in the browser.
---

`fireemu up` serves the Emulator UI at `http://127.0.0.1:4000/ui/`.

```sh
# Another port
npx fireemu up --ui-port 4001

# No UI
npx fireemu up --ui-port 0

# exec starts no UI unless asked
npx fireemu exec --ui -- npm test
```

If the default port is busy, `up` starts without the UI; check the startup output.

## What it shows

- **Overview:** the project, version, virtual clock (frozen, or following real time) and running services, and the `Host` names the emulators answer: the built-in names, the entries you added with `network.allowedHosts` and whether single-label names are allowed.
- **Authentication, Firestore and Storage:** browse and manage users, documents and objects.
- **Functions:** registered functions with the runtime of each (Node.js or Python, and the `runtime` your `firebase.json` declares), their triggers, invocation results and logs, and the runtime status: work pending, running, waiting for a retry or dead-lettered, Auth events held while the event queue is full, tasks in flight, the state of each codebase's runner, and the exports the runner found and could not serve. Run a scheduled function immediately, or advance the clock to its next occurrence.
- **Hosting:** the site Fireemu serves, its local URL, the public directory (with a warning when it did not exist at start), and the rewrites, redirects and headers in the order they apply. The page reads your `firebase.json`; it does not record requests.
- **Realtime Database:** browse the data at a path, replace, patch or delete it as the local administrator, read and replace the instance's Rules, and run an anonymous request to see how the Rules answer it.
- **Alerts:** publish Firebase alerts to functions that listen for them.
- **Rules:** the newest 100 traced Firestore Security Rules decisions, with bounded expression results. Tracing starts with the UI or the first control-API read; a new ruleset clears the history. See [Security Rules](../security-rules/) for diagnostic limits.
- **App Check:** registered apps and debug tokens.
- **Runtime:** the virtual clock. Move it forward, or backwards with **Allow moving backwards**. Under **Fault plan**, select a recipe for retrying a Functions event, duplicate delivery, delaying or timing out an attempt, or failing the first attempts, and enter its parameters. **Fill plan** puts the plan in the JSON editor; it does not install it. Review or edit the JSON and choose **Install** to apply it to the selected session. A parseable plan also offers copyable `fireemu/testing` and control API snippets for installing the same plan from a test; **Clear** removes the installed plan.
