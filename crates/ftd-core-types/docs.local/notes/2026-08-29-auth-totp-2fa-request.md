# メモ: Firebase Auth TOTP 2FA（MFA）対応の要望

- 記録日: 2026-08-29
- 出所: ユーザーからの口頭要望（仕様書v0.3.1の実装作業中）

## 要望

公式Firebase Emulator SuiteのAuth EmulatorはTOTPによる2要素認証（multi-factor TOTP）を再現できず不満点である。firebase-testdで解決できるとよい。

## 仕様書との関係

- `docs.local/firebase-testd-spec-v0.3.1-ja.md` 1.3「非目標」に「Firebase Auth、Realtime Database、Hosting、Remote Config等の再実装」が明記されており、Auth全体が初期scope外。
- したがってTOTP 2FAは現行仕様に記載なし。Capability IDも未採番。

## 次版（v0.4.x以降）で検討すべき論点

- 新Capability ID案: `AUTH-CORE-1`（sign-in／ID token／custom claims）、`AUTH-MFA-TOTP-1`（TOTP enrollment／sign-in second factor）、`AUTH-MFA-SMS-0`（scope外宣言）。
- Identity Toolkit REST（`accounts:*`, `mfaEnrollment:*`, `mfaSignIn:*`）のうち、Client SDK（`multiFactor().enroll`, `TotpMultiFactorGenerator`）とAdmin SDK（`updateUser({multiFactor})`）が実際に叩くsubsetの特定。
- TOTP secret生成、`otpauth://` URI、RFC 6238検証（time step 30s、window、SHA-1、6桁）を仮想時計（`Clock` trait）で決定的にする設計。仮想時計との整合はfirebase-testdの強み。
- ID tokenの`firebase.sign_in_second_factor = "totp"`、`amr` claimの再現。
- Security Rulesの`request.auth.token.firebase.sign_in_second_factor`をnative Rulesで評価可能にする。
- secretをtrace／snapshotに平文で残さない（33章のredaction hookと整合）。
- conformance: 実Firebase AuthのTOTP MFAはIdentity Platform（Blaze）が必要なため、real-service fixtureは課金・opt-inが前提。

## 状態

- 未着手。仕様書へ反映するかはユーザー判断待ち。
