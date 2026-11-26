# Drop Porter

**Windows PCとiPhoneなどのAirDrop対応機器の間で、写真や動画、書類などのファイルを送受信できます。**

現在対応しているWi-Fi子機はArcher TX10UB NanoとArcher TX20U Nano V1の2機種です。Bluetoothも必要です。

## 対応するWi-Fi子機とドライバー

<table>
  <thead>
    <tr><th>Wi-Fi子機</th><th>純正ドライバーのバージョン</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://www.tp-link.com/jp/support/download/archer-tx10ub-nano/">TP-Link Archer TX10UB Nano</a></td>
      <td>
        <div>5001.19.113.1（<a href="https://www.tp-link.com/jp/support/download/archer-tx10ub-nano/">日本向け</a>）</div>
        <div>5001.19.113.1（<a href="https://www.tp-link.com/us/support/download/archer-tx10ub-nano/v1.60/">米国向け 20240621 版</a>）</div>
      </td>
    </tr>
    <tr>
      <td><a href="https://www.tp-link.com/jp/support/download/archer-tx20u-nano/">TP-Link Archer TX20U Nano V1</a></td>
      <td>
        <div>5001.19.128.4</div>
        <div>5001.19.128.1</div>
        <div>5001.19.113.2</div>
      </td>
    </tr>
  </tbody>
</table>

## Windows版のダウンロード

Windows x64版をダウンロードできます。[DropPorter-0.2.0-Windows-x64.zip](https://github.com/dtstudio-git/DropPorter/releases/download/v0.2.0/DropPorter-0.2.0-Windows-x64.zip)

ZIPを展開し、子機をPCに接続してから `DropPorter.exe` を起動してください。[起動手順とドライバーの案内](docs/DropPorter_Readme.txt)

## 使用時のWi-Fi接続

送受信を始めると、Windowsが管理者権限の許可を求めます。使用する子機のWi-Fi接続は送受信中に一時的に切れ、終了すると元の状態に戻ります。

続けて送受信するときは、設定で「送受信のたびにWi-Fiを元に戻さない」をオンにすると、待ち時間を短くできます。アプリを閉じるか設定をオフにすると、子機は送受信を始める前の状態に戻ります。

## ビルド

ビルドには、Visual Studio 2026の「C++によるデスクトップ開発」、MSVC v145、Windows SDK 10.0.28000.0、.NET 10 SDKが必要です。Visual Studioの開発者コマンドプロンプトを開き、リポジトリのルートで次を実行します。

```cmd
MSBuild.exe tools/DropPorterWpf.proj
```

ビルドしたアプリは `tools\human-check.cmd` から起動できます。

## ライセンス

Drop Porter本体はMITライセンスです。[LICENSE](LICENSE)

同梱するライブラリには、それぞれのライセンスが適用されます。

- lwIP 2.2.1 [BSD 3-Clauseライセンス](third_party/lwip/COPYING)
- zlib 1.4 [zlibライセンス](third_party/zlib/LICENSE)

Windows App SDKとCoreJ2KはNuGetで復元します。[WPFプロジェクト](ui/DropPorter.Wpf/DropPorter.Wpf.csproj)

AirDropとの相互運用にあたり、以下のプロジェクトを参考にしました。[OWL](https://github.com/seemoo-lab/owl) · [OpenDrop](https://github.com/seemoo-lab/opendrop)
