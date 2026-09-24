# RedstoneTweaksMod (LeviLaunchroid native mod)

Redstone Tweaks (Java版リソースパック by RexxStone v2.5.5) の「オフセット/シグネチャが要らない部分」を
先に形にして、あとから信号強度表示などを追加していくためのプロジェクト。

## 現状

LiteLDev/LeviLaunchroid公式の `examples/full-cpp-mod`(動作確認済みのコード)を土台に、
最小構成へ整理・リネームした状態です。

- `manifest.json` : mod名/entryをRedstoneTweaksMod用に変更
- `src/RedstoneTweaksMod.cpp` : Mod Menuに「Redstone Tweaks Info」として登録されるだけの
  最小モジュール(公式サンプルにあった複数デモ用HUDボタンは削除)
- `src/RedstoneTweaksConfig.hpp` : `enabled`だけの最小設定
- `src/GenerateConfig.cpp` : config.json/config.schema.json生成用(公式サンプルと同じ仕組み)
- `CMakeLists.txt` / `build.ps1` : 公式サンプルからコピーし、依存パスをこのリポジトリ単独で
  完結するように変更(下記参照)

### 公式サンプルから変えた点

公式サンプルは LeviLaunchroid 本体リポジトリの中にネストされている前提で、
`preloader-android`(`pl::Mod.hpp`等の実装がある別リポジトリ)を
`../../app/src/main/cpp/preloader` から見つけていました。
ウチは単独リポジトリなので、代わりに `third_party/preloader-android` に
別途配置する前提に変更しています。

## タブレット運用が前提の作業フロー

NDK/CMakeでのビルドは**手元では一切やらない**。GitHub Actions(クラウド側)が
全部代わりにビルドしてくれる構成にしてある。タブレット側でやることは
「ファイルをGitHubリポジトリに置く」だけ:

1. GitHubで新規リポジトリを作る
2. このzipの中身(`.github`, `src`, `manifest.json`, `CMakeLists.txt`, `build.ps1`, `README.md`)を、
   GitHubのブラウザ版(または公式アプリ)の「Add file → Upload files」でそのままアップロード
   - フォルダごとドラッグ&ドロップに対応してるブラウザなら`src/`や`.github/`の階層もそのまま持っていける
3. コミットすれば、`.github/workflows/build.yml`が自動で動き出す
   - このワークフローは自分自身のリポジトリに加えて`LiteLDev/preloader-android`も
     CI側で別途チェックアウトするようにしてあるので、**submoduleのローカル操作は不要**
4. ビルドが終わったら、Actionsのページ(または`v0.0.1`のようなタグをpushしてReleaseページ)から
   `RedstoneTweaksMod.levipack`をダウンロードできる

`build.ps1`はPCでローカルビルドしたくなったとき用に残してあるだけで、タブレットのみの運用では使わない。

## まだ手つかず

`redstone_wire`の信号強度など、ワールド内のブロック状態を読んで描画に反映する機能は未実装です。
`examples/full-cpp-mod`には該当する処理が元々なく、`third_party/preloader-android`の
Hook API(まだ中身を確認していない)を読んで、どこまでワールドデータ・レンダリングに
手が届くか調べるところから。進捗は会話メモリ(`/areas/redstone-tweaks-bedrock.md`)にも残してあります。
