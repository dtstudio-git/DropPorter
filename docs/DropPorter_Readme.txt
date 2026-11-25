Drop Porter 0.1.0 for Windows x64

必要なもの
  対応するWi-Fi子機と純正ドライバー（別途導入）
    TP-Link Archer TX10UB Nano
      5001.19.113.1（日本向け）
      https://www.tp-link.com/jp/support/download/archer-tx10ub-nano/
      5001.19.113.1（米国向け 20240621 版）
      https://www.tp-link.com/us/support/download/archer-tx10ub-nano/v1.60/
    TP-Link Archer TX20U Nano V1
      5001.19.128.4、5001.19.128.1、5001.19.113.2
      https://www.tp-link.com/jp/support/download/archer-tx20u-nano/
  Bluetooth

起動手順
  1. ZIPの内容をすべて展開します。
  2. 対応するWi-Fi子機を接続し、展開先の DropPorter.exe を起動します。
     送信・受信はどちらも、Windows の NdisCap を使います。
     送受信を始めるときにWindowsの管理者権限の確認が表示されます。
     対応ドライバーを使う子機が複数ある場合は、Wi-Fiに接続していない子機を優先します。

.NETのインストールは不要です。

送受信中は使用するWi-Fi子機の接続が一時的に切断されます。
処理を終えると、Drop Porterが使用した子機を元の接続状態に戻します。
起動前にWi-Fiに接続していなかった子機は、未接続の状態に戻ります。

ドライバーが対応外と表示された場合
  結果欄の「ドライバーを戻す手順」を開いてください。
  以前のドライバーに戻せない場合は、上記のTP-Link公式ページで
  お使いの子機に対応するドライバーを入手してください。
