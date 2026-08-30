import type { ResultAsync } from "neverthrow";
import { request, type ApiError, type Json } from "./client";

export type ProviderInfo = {
  providerId: string;
  rawId?: string;
  email?: string;
  displayName?: string;
  federatedId?: string;
};

export type MfaEnrollment = {
  mfaEnrollmentId: string;
  displayName?: string;
  phoneInfo?: string;
  totpInfo?: Record<string, unknown>;
  enrolledAt?: string;
};

export type UserInfo = {
  localId: string;
  email?: string;
  emailVerified?: boolean;
  phoneNumber?: string;
  displayName?: string;
  photoUrl?: string;
  disabled?: boolean;
  customAttributes?: string;
  createdAt?: string;
  lastLoginAt?: string;
  validSince?: string;
  providerUserInfo?: ProviderInfo[];
  mfaInfo?: MfaEnrollment[];
};

export type UserPage = { users?: UserInfo[]; nextPageToken?: string };

export type OobCodeInfo = {
  email: string;
  requestType: string;
  oobCode: string;
  oobLink: string;
};

export type VerificationCodeInfo = { phoneNumber: string; sessionInfo: string; code: string };

const admin = (project: string): string =>
  `auth/identitytoolkit.googleapis.com/v1/projects/${encodeURIComponent(project)}`;
const emulator = (project: string): string =>
  `auth/emulator/v1/projects/${encodeURIComponent(project)}`;

export const listUsers = (project: string, pageToken?: string): ResultAsync<UserPage, ApiError> => {
  const params = new URLSearchParams({ maxResults: "50" });
  if (pageToken) {
    params.set("nextPageToken", pageToken);
  }
  return request<UserPage>("GET", `${admin(project)}/accounts:batchGet?${params.toString()}`);
};

/** Looks a user up by email, phone number (`+...`) or UID. */
export const lookupUser = (project: string, query: string): ResultAsync<UserPage, ApiError> => {
  const q = query.trim();
  const body = q.includes("@")
    ? { email: [q] }
    : q.startsWith("+")
      ? { phoneNumber: [q] }
      : { localId: [q] };
  return request<UserPage>("POST", `${admin(project)}/accounts:lookup`, body);
};

export type NewUser = {
  email?: string;
  password?: string;
  phoneNumber?: string;
  displayName?: string;
  localId?: string;
  emailVerified?: boolean;
};

export const createUser = (
  project: string,
  user: NewUser,
): ResultAsync<{ localId: string }, ApiError> =>
  request("POST", `${admin(project)}/accounts`, user);

export type UserUpdate = {
  localId: string;
  email?: string;
  password?: string;
  phoneNumber?: string;
  displayName?: string;
  photoUrl?: string;
  emailVerified?: boolean;
  disableUser?: boolean;
  customAttributes?: string;
  deleteAttribute?: string[];
  mfa?: { enrollments: MfaEnrollment[] };
};

export const updateUser = (project: string, update: UserUpdate): ResultAsync<Json, ApiError> =>
  request("POST", `${admin(project)}/accounts:update`, update);

export const deleteUser = (project: string, localId: string): ResultAsync<Json, ApiError> =>
  request("POST", `${admin(project)}/accounts:delete`, { localId });

export const deleteAllUsers = (project: string): ResultAsync<Json, ApiError> =>
  request("DELETE", `${emulator(project)}/accounts`);

export const listOobCodes = (project: string): ResultAsync<{ oobCodes: OobCodeInfo[] }, ApiError> =>
  request("GET", `${emulator(project)}/oobCodes`);

export const listVerificationCodes = (
  project: string,
): ResultAsync<{ verificationCodes: VerificationCodeInfo[] }, ApiError> =>
  request("GET", `${emulator(project)}/verificationCodes`);

export const getConfig = (project: string): ResultAsync<Json, ApiError> =>
  request("GET", `${emulator(project)}/config`);

export const patchConfig = (project: string, config: unknown): ResultAsync<Json, ApiError> =>
  request("PATCH", `${emulator(project)}/config`, config);
