# Production comparison audit

Task: **COMPAT-COMPARE-AUDIT-001**

保存本番比較pilot `PROD-DIFF-PILOT-001` の検出力を、決定的な反例で点検する。
既存の比較器・保存Oracle・live collectorを変更せず、本番にも公式Emulatorにも通信しない。
対応は `fs.batch-write.saved-20260907.v1` の全5ステップだけ。万能なmutation frameworkは追加しない。

## 何を検証するか

`production-diff/legacy.mjs` の既存 `prepare()` が、保存matrix、観測当時のprogram、
既存recorder、比較関数のpinを検査する。そのproduction projectionから**テスト用のlocal対照**を
作り、一度に一箇所の応答または記録条件を変更する。

- HTTP status、canonical code、拒否／受理、返却値・型・欠落、拒否後の文書状態。
- 行の欠落・追加・順序、未完了応答、setup失敗。
- 同じcase IDのまま操作列・seedを変更したときのOracle結合拒否。
- cleanup／process／executionが未確定のときの受入拒否。
- JSON objectのキー順と、旧比較契約が除外しているerror proseの許容。

**本番の応答をlocal対照へコピーするのはテスト用の基準入力を作るためだけであり、fireemuを
実行して一致を確認したことではない。** 元のOracle、receipt、runを上書きしない。
コピーした対照や変異応答を互換性の証拠として登録してはいけない。

## 実行

先行pilotが同じcheckoutの `conformance/production-diff/` に統合されている必要がある。
従来pilotの `plan` に必要な、完全な保存matrixと歴史的Git objectを使う。
不足していたらINDETERMINATEで停止し、fixtureやlive取得へfallbackしない。

```sh
# Node 22+。モデル、Java、native fireemu、追加npm依存は不要。
node --test conformance/production-diff-audit/test/audit.test.mjs

# 親ディレクトリは存在し、出力ディレクトリ自体は新規かつrepo外であること。
node conformance/production-diff-audit/audit.mjs \
  --out /absolute/private/new-comparison-audit
```

`--repo /absolute/checkout` は対象データとpilotのcheckout指定。実行されたauditソースと、
選択checkoutのpilotソースを別々にhashする。通常は省略する。
読み取るのは信頼できる、レビューされたrepoに限る。任意の悪意あるJavaScript向けのsandboxではない。

CLIからnative binary、別backend、任意plugin、ネットワーク接続先、fixture modeは指定できない。
既存pilotの純粋な比較経路のみを呼び、`replay` や `record-production` は呼ばない。
Gitは既存の `prepare()` によるローカルobjectの読取りのみ。fetchしない。

`report.md` の後に、最終ファイルとして `result.json` を原子的・上書きなしで公開する。
出力が部分的、保存失敗、source変更、pin不一致の場合は終了コード0を返さない。
stdoutは短い件数・判定だけ。JSON結果にはraw応答や元の例外・秘密情報を含めない。

| Exit | 意味 |
|---|---|
| 0 | 対応した反例・正常対照をすべて期待どおり処理した |
| 1 | 監査を実行できたが、見逃し・誤判定・反例実行エラーがあった |
| 2 | 前提不足、基準入力不成立、source変更、実行・保存失敗などで評価不能 |

## 結果の数え方

75プローブの内訳は、現在の固定pilotに対して次のとおり。

| Group | 数 | 期待する結果 |
|---|---:|---|
| semantic | 34 | MISMATCH。旧正規化後に残る値・構造の改変を検出 |
| integrity | 26 | INDETERMINATE。不完全・不正な実行記録を拒否 |
| binding | 3 | 特定の既存validation errorによるREFUSED |
| envelope | 5 | 実行・回収・プロセス終了の不足をINDETERMINATEにする |
| tolerance | 7 | MATCH。比較対象外の診断文やobjectキー順だけで落とさない |

これは**34種類のソースコードmutationを実行したという意味ではない**。
応答／記録層へのfault injectionであり、runtimeのmutation kill率とも互換率とも異なる。

有効な応答改変で例外・INDETERMINATEが起きても検出成功に数えない。
すべてをMISMATCHにする比較器は基準入力で落とし、すべてをMATCHにする比較器は反例で落とす。
変異がno-opならNO_OPとして失敗させる。必須probeを黙ってskipしない。

結果には `evidenceKind: comparator-response-mutation-audit` と、以下を必ず残す。

```json
{
  "productionExecuted": false,
  "nativeRuntimeExecuted": false,
  "freshLocalExecution": false,
  "acquisitionValidated": false,
  "parentPromotion": false,
  "compatibilityEstablished": false,
  "baselineKind": "synthetic-local-control-from-saved-production-projection"
}
```

`auditPassed` を `gatePassed` や `COMPAT_VERIFIED` へ変換しない。
G1/G2・FS-DATA-WRITE全体を閉じるものではない。

## 明示する未検証事項

このpilotには結果順序をもつ成功配列がないため、配列順の検出力は **not exercised**。
時刻関係は旧normalizerが消しているため、この監査では復元できない。
`<now>`の型・欠落を検査しても、時刻や期限の正しさを検証したことにはしない。
error proseは既存契約の対象外として許容する。その7対照は検出件数に加えない。
Auth／Rules／tenant主体、Listen、SDK、並行履歴、合法なBatchWriteの部分成功、
Commit field-transform 500/501はこのsuiteのカバレッジに含めない。

## 統合と分担

変更対象は `conformance/production-diff-audit/` の新規ファイルだけ。
先行pilot、共有Gate/Ledger、Rules/Lifecycle比較器、local-assist、runtime、台帳、CIは変更しない。
共有済み5件の修正と競合せず、既存G1/G2を止める前提も増やさない。

先行pilotがレビュー・統合されたら、本suiteを別の変更としてレビュー・統合する。
pilotのAPI/pinが変わった場合は現行コードにadapterを合わせ、反例の意味を確認する。
古いソースへ巻き戻したり、失敗を消すためだけにpinを書き換えたりしない。

将来、実装者がcomparison contractを変更する際にこの監査を使う。
全caseへの一般化やCI required化は今回の必須作業にしない。
