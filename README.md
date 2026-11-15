# SigmaOS-linux-arch

> **Arch Linux tooling suite** for SigmaOS — pacman, mkinitcpio, archinstall, AUR, namcap.

Part of the [SigmaOS](https://github.com/AaryanSinghChauhan09/SigmaOS) ecosystem.

## Modules

| Module | Description |
|---|---|
| `pacman` | libalpm descriptor parsing, version comparison, dependency transactions |
| `mkinitcpio` | Initramfs hook dependency solver & early ramfs generation |
| `archinstall` | Declarative installation profiles, disk partition schemes |
| `contrib` | paccache, checkupdates, rankmirrors, pactree utilities |
| `audit` | Arch Security Advisory CVE vulnerability scanner |
| `namcap` | Package metadata & FHS layout quality linter |

## Quickstart

```bash
cargo test    # all 6+ deterministic AAA unit tests
cargo check   # compilation check
```

## API Example

```rust
use sigmaos_linux_arch::{AlpmVersion, PacmanBridge, ArchAuditScanner};

let v1 = AlpmVersion::new("1.5.0");
let v2 = AlpmVersion::new("1.6.0");
assert!(v1 < v2);  // version ordering

let bridge = PacmanBridge::new("/var/lib/pacman");
```

## License

MIT
