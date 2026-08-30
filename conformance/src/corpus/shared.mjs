// SDK handles shared by every scenario in one run, created once and lazily.
//
// One process runs the whole corpus against one emulator instance, so the apps are created
// once: a second `initializeApp` with the same name is an SDK error, and a fresh gRPC channel
// per scenario would change what the Listen rows observe.

import { initializeApp as initializeAdminApp } from "firebase-admin/app";
import { getFirestore as getAdminFirestore } from "firebase-admin/firestore";
import { getAuth as getAdminAuth } from "firebase-admin/auth";
import { getStorage as getAdminStorage } from "firebase-admin/storage";
import { initializeApp } from "firebase/app";
import { connectAuthEmulator, getAuth } from "firebase/auth";
import { connectFirestoreEmulator, getFirestore } from "firebase/firestore";
import {
  connectFirestoreEmulator as connectLiteEmulator,
  getFirestore as getLiteFirestore,
} from "firebase/firestore/lite";
import { connectStorageEmulator, getStorage } from "firebase/storage";

import { BUCKET, PROJECT } from "../config.mjs";

const splitHost = (hostPort) => {
  const index = hostPort.lastIndexOf(":");
  return [hostPort.slice(0, index), Number(hostPort.slice(index + 1))];
};

/**
 * Creates the shared handles. `hosts` comes from the supervisor's environment, so the same
 * code addresses the official suite and fireemu.
 */
export function createShared(hosts) {
  const cache = new Map();
  const once = (key, make) => {
    if (!cache.has(key)) cache.set(key, make());
    return cache.get(key);
  };

  const adminApp = () =>
    once("adminApp", () =>
      initializeAdminApp({ projectId: PROJECT, storageBucket: BUCKET }, "conformance-admin"),
    );

  const webApp = () =>
    once("webApp", () => {
      const app = initializeApp(
        { projectId: PROJECT, apiKey: "fake-api-key", storageBucket: BUCKET },
        "conformance-web",
      );
      connectAuthEmulator(getAuth(app), `http://${hosts.auth}`, { disableWarnings: true });
      const [fsHost, fsPort] = splitHost(hosts.firestore);
      connectFirestoreEmulator(getFirestore(app), fsHost, fsPort);
      const [stHost, stPort] = splitHost(hosts.storage);
      connectStorageEmulator(getStorage(app), stHost, stPort);
      return app;
    });

  // Firestore Lite speaks REST only and needs its own app: one `firebase` app cannot host
  // both the full and the lite Firestore instance.
  const liteApp = () =>
    once("liteApp", () => {
      const app = initializeApp({ projectId: PROJECT, apiKey: "fake-api-key" }, "conformance-lite");
      connectAuthEmulator(getAuth(app), `http://${hosts.auth}`, { disableWarnings: true });
      return app;
    });

  return {
    adminApp,
    adminFirestore: () => once("adminFirestore", () => getAdminFirestore(adminApp())),
    adminAuth: () => once("adminAuth", () => getAdminAuth(adminApp())),
    adminBucket: () => once("adminBucket", () => getAdminStorage(adminApp()).bucket()),
    webApp,
    webAuth: () => getAuth(webApp()),
    webFirestore: () => getFirestore(webApp()),
    webStorage: () => getStorage(webApp()),
    liteAuth: () => getAuth(liteApp()),
    liteFirestore: () =>
      once("liteFirestore", () => {
        const db = getLiteFirestore(liteApp());
        const [host, port] = splitHost(hosts.firestore);
        connectLiteEmulator(db, host, port);
        return db;
      }),
    // Scratch space one row fills in for the next (a uid, an upload session URL).
    scratch: {},
  };
}
