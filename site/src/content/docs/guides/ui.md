---
title: Emulator UI
description: Inspect and manage data, Functions, Security Rules decisions and the clock in the browser.
---

`fireemu up` serves the Emulator UI at `http://127.0.0.1:4000`.

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

- **Overview:** the project, version, virtual clock and running services.
- **Authentication, Firestore and Storage:** browse and manage users, documents and objects.
- **Functions:** registered functions, their triggers, invocation results and logs. Run a scheduled function immediately, or advance the clock to its next occurrence.
- **Alerts:** publish Firebase alerts to functions that listen for them.
- **Rules:** every Security Rules decision since the start of the run, with what each expression evaluated to.
- **App Check:** registered apps and debug tokens.
- **Runtime:** the virtual clock. Move it forward, or backwards with **Allow moving backwards**.
