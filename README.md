# Warpshot

Fast, end-to-end encrypted transfer of screenshots, text and files between your
**Android phone** and your **Windows PC** — one hotkey, no window, no account.

> **Status:** design phase (Faz 0). There is no runnable code yet. Start with
> [`docs/architecture.md`](docs/architecture.md).

## What it will do

- **PC → phone:** take a screenshot (`Win+Shift+S`) and press your hotkey. A few
  seconds later it is on your phone: in the gallery, on the clipboard, and in a
  notification with a preview.
- **Phone → PC:** tap Share and pick your PC directly in the share sheet. The
  item lands in your PC's clipboard and `Downloads\Warpshot`.
- **See your devices** and whether they are online or can be woken up.

## Design highlights

- **Direct P2P** over [iroh](https://iroh.computer) (QUIC + TLS 1.3): direct on
  the same Wi-Fi, NAT traversal across networks, an end-to-end encrypted relay as
  a last resort. Relaying data can be turned off.
- **Post-quantum inner layer:** an X-Wing (X25519 + ML-KEM-768) handshake inside
  TLS, so recorded traffic stays private even against future quantum computers.
- **No accounts, no passwords:** devices form a group by scanning a QR code. The
  group is a member-signed, hash-chained log. The server cannot add devices or
  read anything.
- **$0 server:** a tiny Cloudflare Worker that only authenticates, keeps the
  membership log and wakes devices up.
- **Featherweight Windows agent:** < 5 MB RAM and ≈ 0 network while idle. These
  targets are measured, not guessed.

## Documents

| | |
|---|---|
| [Architecture](docs/architecture.md) | components, flows, storage |
| [Protocol](docs/protocol.md) | normative wire and crypto spec |
| [Threat model](docs/threat-model.md) | what we defend against |
| [Resource budget](docs/resource-budget.md) | the Windows idle budget and how it is measured |
| [Decisions](docs/adr/) | ADRs |
| [Roadmap](docs/roadmap.md) | phases and tasks with acceptance criteria |
| [Dev setup](docs/dev-setup.md) | toolchain, downloads, accounts |

## Türkçe özet

Telefon (Android) ile bilgisayar (Windows) arasında ekran görüntüsü, metin ve
dosya gönderen açık kaynak bir uygulama:

- **PC'den telefona:** panodaki içerik tek kısayolla, hiç pencere açılmadan önceden seçilmiş telefona gider.
- **Telefondan PC'ye:** paylaş menüsünden PC'yi seçmek yeterli.
- **Bağlantı:** P2P, uçtan uca ve kuantum sonrası hibrit şifreli.
- **Hesap yok:** cihazlar QR ile eşleşir.
- **Sunucu:** maliyeti $0.
- **Windows tarafı:** boştayken 5 MB'ın altında RAM kullanır, ağ trafiği neredeyse sıfırdır.

## License

GPL-3.0-or-later (see [`LICENSE`](LICENSE)), with an additional permission for
linking the Google Play Services and Firebase client libraries
([`LICENSE-ADDITIONAL-PERMISSION.md`](LICENSE-ADDITIONAL-PERMISSION.md)).
Security reports: [`SECURITY.md`](SECURITY.md).
