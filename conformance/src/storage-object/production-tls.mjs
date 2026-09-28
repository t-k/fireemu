import tls from "node:tls";

export const PRODUCTION_WIRE_ORIGINS = Object.freeze([
  "https://firebasestorage.googleapis.com",
  "https://storage.googleapis.com",
  "https://identitytoolkit.googleapis.com",
  "https://securetoken.googleapis.com",
  "https://oauth2.googleapis.com",
  "https://firebaserules.googleapis.com",
  "https://apikeys.googleapis.com",
  "https://cloudresourcemanager.googleapis.com",
]);
const TLS_ENV_OVERRIDES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_OPTIONS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "OPENSSL_ENGINES",
];

/** No system/extra CA, localhost SNI or provider override is admitted by production factories. */
export function productionTlsOptions(value) {
  try {
    if (
      process.version !== "v24.14.0" ||
      process.execArgv.length !== 0 ||
      typeof value !== "string" ||
      TLS_ENV_OVERRIDES.some((key) => process.env[key] !== undefined)
    )
      throw new Error();
    const url = new URL(value);
    if (!PRODUCTION_WIRE_ORIGINS.includes(url.origin) || url.username || url.password || url.hash)
      throw new Error();
    return Object.freeze({
      servername: url.hostname,
      rejectUnauthorized: true,
      checkServerIdentity: tls.checkServerIdentity,
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
      ca: Object.freeze(tls.getCACertificates("bundled")),
    });
  } catch {
    throw new Error("invalid production TLS policy");
  }
}
