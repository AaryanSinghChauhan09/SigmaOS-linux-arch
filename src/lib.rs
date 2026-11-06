//! SigmaOS Linux Arch Compatibility & Tooling Suite
//! Direct inspiration: https://github.com/orgs/archlinux/repositories
//!
//! Subsystems:
//! - `pacman`: libalpm package descriptor parsing, version comparison, and dependency transactions
//! - `mkinitcpio`: Initramfs hook dependency solver and early ramfs generation
//! - `archinstall`: Declarative installation profiles and disk partition schemes
//! - `contrib`: Pacman utilities (paccache, checkupdates, rankmirrors, pactree)
//! - `audit`: Arch Security Advisory (ASA) CVE vulnerability scanner
//! - `namcap`: Package metadata and FHS layout quality linter

pub mod pacman;
pub mod mkinitcpio;
pub mod archinstall;
pub mod contrib;
pub mod audit;
pub mod namcap;

// Re-exports
pub use pacman::{
    AlpmDependency, AlpmTransaction, AlpmVersion, ArchPackageDesc, DepOperator,
    PacmanConfig, PacmanRepo, TransactionAction,
};
pub use mkinitcpio::{InitramfsHook, MkinitcpioConfig, MkinitcpioHookSolver};
pub use archinstall::{
    ArchinstallProfile, DesktopEnvironment, FilesystemKind, NetworkManagerType,
    ProfileKind, SubvolumeConfig,
};
pub use contrib::{
    CachedPackageFile, CheckUpdates, MirrorEntry, PacCache, PacTree, PendingUpdate,
    RankMirrors,
};
pub use audit::{ArchAuditScanner, SecurityAdvisory, Severity, VulnerabilityReport};
pub use namcap::{LintTag, NamcapLinter, TagLevel};

// Legacy compatibility shim for PacmanBridge
#[derive(Debug, Clone, PartialEq)]
pub struct ArchPackageMeta {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub dependencies: Vec<String>,
}

pub struct PacmanBridge {
    pub db_path: String,
}

impl PacmanBridge {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self { db_path: db_path.into() }
    }

    pub fn parse_desc(&self, raw: &str) -> Option<ArchPackageMeta> {
        let desc = ArchPackageDesc::parse(raw).ok()?;
        Some(ArchPackageMeta {
            name: desc.name,
            version: desc.version,
            architecture: desc.arch,
            dependencies: desc.depends.into_iter().map(|d| d.name).collect(),
        })
    }
}

// =========================================================================
// UNIT TESTS (Arrange-Act-Assert Pattern)
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_pacman_bridge() {
        // Arrange
        let bridge = PacmanBridge::new("/var/lib/pacman");
        let raw = "%NAME%\ncoreutils\n%VERSION%\n9.4-1\n%ARCH%\nx86_64\n%DEPENDS%\nglibc\n";
        // Act
        let pkg = bridge.parse_desc(raw).unwrap();
        // Assert
        assert_eq!(pkg.name, "coreutils");
        assert_eq!(pkg.version, "9.4-1");
        assert_eq!(pkg.dependencies, vec!["glibc"]);
    }

    #[test]
    fn test_alpm_vercmp_epoch_and_segments() {
        // Arrange: epoch beats pkgver, numeric segments beat alpha
        let v1 = AlpmVersion::parse("1:1.0-1");
        let v2 = AlpmVersion::parse("2.0-1");
        let v3 = AlpmVersion::parse("2.10.0-1");
        let v4 = AlpmVersion::parse("2.9.0-1");

        // Act & Assert
        assert_eq!(v1.compare(&v2), std::cmp::Ordering::Greater);
        assert_eq!(v3.compare(&v4), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_alpm_dependency_constraints() {
        // Arrange
        let dep_gte = AlpmDependency::parse("glibc>=2.38");
        let dep_exact = AlpmDependency::parse("python=3.12.0");

        // Act & Assert
        assert!(dep_gte.is_satisfied_by("glibc", "2.39-1"));
        assert!(dep_gte.is_satisfied_by("glibc", "2.38-1"));
        assert!(!dep_gte.is_satisfied_by("glibc", "2.37-1"));
        assert!(!dep_gte.is_satisfied_by("musl", "2.39-1"));

        assert!(dep_exact.is_satisfied_by("python", "3.12.0-1"));
        assert!(!dep_exact.is_satisfied_by("python", "3.11.0-1"));
    }

    #[test]
    fn test_pacman_conf_parser() {
        // Arrange
        let conf = r#"
[options]
RootDir = /
DBPath = /var/lib/pacman
Color
ParallelDownloads = 10
HoldPkg = pacman glibc linux

[core]
Server = https://geo.mirror.pkg.archlinux.org/core/os/x86_64
SigLevel = Required DatabaseOptional

[extra]
Server = https://geo.mirror.pkg.archlinux.org/extra/os/x86_64
"#;

        // Act
        let parsed = PacmanConfig::parse(conf);

        // Assert
        assert!(parsed.color);
        assert_eq!(parsed.parallel_downloads, 10);
        assert_eq!(parsed.hold_pkgs, vec!["pacman", "glibc", "linux"]);
        assert_eq!(parsed.repositories.len(), 2);
        assert_eq!(
            parsed.repositories.get("core").unwrap().servers[0],
            "https://geo.mirror.pkg.archlinux.org/core/os/x86_64"
        );
    }

    #[test]
    fn test_alpm_transaction_topological_sort() {
        // Arrange
        let mut tx = AlpmTransaction::new();
        let glibc = ArchPackageDesc {
            name: "glibc".to_string(),
            version: "2.39-1".to_string(),
            ..Default::default()
        };
        let libssl = ArchPackageDesc {
            name: "openssl".to_string(),
            version: "3.2.0-1".to_string(),
            depends: vec![AlpmDependency::parse("glibc")],
            ..Default::default()
        };
        let curl = ArchPackageDesc {
            name: "curl".to_string(),
            version: "8.6.0-1".to_string(),
            depends: vec![AlpmDependency::parse("openssl"), AlpmDependency::parse("glibc")],
            ..Default::default()
        };

        tx.register_installed(glibc);
        tx.register_installed(libssl);
        tx.register_installed(curl.clone());

        // Act
        tx.stage_install(curl).unwrap();
        let order = tx.resolve_order();

        // Assert: glibc must precede openssl, openssl must precede curl
        let glibc_idx = order.iter().position(|x| x == "glibc").unwrap();
        let ssl_idx = order.iter().position(|x| x == "openssl").unwrap();
        let curl_idx = order.iter().position(|x| x == "curl").unwrap();

        assert!(glibc_idx < ssl_idx);
        assert!(ssl_idx < curl_idx);
    }

    #[test]
    fn test_mkinitcpio_hook_ordering_and_dependencies() {
        // Arrange
        let solver = MkinitcpioHookSolver::standard();
        let hooks = vec![
            "base".to_string(),
            "udev".to_string(),
            "autodetect".to_string(),
            "modconf".to_string(),
            "block".to_string(),
            "filesystems".to_string(),
            "fsck".to_string(),
        ];

        // Act
        let ordered = solver.validate_and_order(&hooks).expect("valid hook order");

        // Assert
        assert_eq!(ordered.len(), 7);
        assert_eq!(ordered[0], "base");
        assert_eq!(ordered[1], "udev");

        // Microcode detection
        assert_eq!(
            solver.detect_microcode_prepend("GenuineIntel"),
            Some("boot/intel-ucode.img")
        );
        assert_eq!(
            solver.detect_microcode_prepend("AuthenticAMD"),
            Some("boot/amd-ucode.img")
        );
    }

    #[test]
    fn test_mkinitcpio_missing_dependency_fails() {
        // Arrange: 'block' hook without prior 'udev' hook
        let solver = MkinitcpioHookSolver::standard();
        let broken_hooks = vec!["base".to_string(), "block".to_string()];

        // Act & Assert
        let res = solver.validate_and_order(&broken_hooks);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("missing required prior hook 'udev'"));
    }

    #[test]
    fn test_archinstall_btrfs_layout_and_fstab() {
        // Arrange
        let profile = ArchinstallProfile::default();

        // Act
        let subvolumes = profile.standard_btrfs_subvolumes();
        let pkgs = profile.required_packages();
        let fstab = profile.generate_fstab("1234-5678", "abcd-ef01");

        // Assert
        assert_eq!(subvolumes.len(), 4);
        assert_eq!(subvolumes[0].name, "@");
        assert_eq!(subvolumes[0].mountpoint, "/");
        assert!(pkgs.contains(&"btrfs-progs"));
        assert!(pkgs.contains(&"pipewire"));
        assert!(fstab.contains("UUID=1234-5678 /boot/efi"));
        assert!(fstab.contains("subvol=@,noatime,compress=zstd:1"));
    }

    #[test]
    fn test_paccache_retention_policy() {
        // Arrange
        let mut cache = PacCache::new(2); // keep latest 2
        cache.add_file(CachedPackageFile {
            pkgname: "linux".to_string(),
            version: "6.8.1-arch1".to_string(),
            arch: "x86_64".to_string(),
            filename: "linux-6.8.1-arch1-x86_64.pkg.tar.zst".to_string(),
            size_bytes: 140_000_000,
        });
        cache.add_file(CachedPackageFile {
            pkgname: "linux".to_string(),
            version: "6.8.2-arch1".to_string(),
            arch: "x86_64".to_string(),
            filename: "linux-6.8.2-arch1-x86_64.pkg.tar.zst".to_string(),
            size_bytes: 140_500_000,
        });
        cache.add_file(CachedPackageFile {
            pkgname: "linux".to_string(),
            version: "6.7.9-arch1".to_string(),
            arch: "x86_64".to_string(),
            filename: "linux-6.7.9-arch1-x86_64.pkg.tar.zst".to_string(),
            size_bytes: 139_000_000,
        });

        // Act
        let candidates = cache.scan_candidates_for_removal();

        // Assert: 6.7.9-arch1 must be purged (keep 6.8.2 and 6.8.1)
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].version, "6.7.9-arch1");
    }

    #[test]
    fn test_checkupdates_diff() {
        // Arrange
        let mut installed = BTreeMap::new();
        installed.insert("systemd".to_string(), "255.4-1".to_string());
        installed.insert("bash".to_string(), "5.2.026-1".to_string());

        let mut sync_db = BTreeMap::new();
        sync_db.insert("systemd".to_string(), "255.4-2".to_string()); // upgrade available
        sync_db.insert("bash".to_string(), "5.2.026-1".to_string());    // up to date

        // Act
        let pending = CheckUpdates::find_updates(&installed, &sync_db);

        // Assert
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "systemd");
        assert_eq!(pending[0].new_version, "255.4-2");
    }

    #[test]
    fn test_rankmirrors_latency_sort() {
        // Arrange
        let mirrors = vec![
            MirrorEntry { url: "https://slow.mirror/arch".to_string(), latency_ms: 350, reachable: true },
            MirrorEntry { url: "https://fast.mirror/arch".to_string(), latency_ms: 22, reachable: true },
            MirrorEntry { url: "https://dead.mirror/arch".to_string(), latency_ms: 0, reachable: false },
            MirrorEntry { url: "https://medium.mirror/arch".to_string(), latency_ms: 85, reachable: true },
        ];

        // Act
        let ranked = RankMirrors::rank(&mirrors);

        // Assert: only reachable sorted by latency
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0], "https://fast.mirror/arch");
        assert_eq!(ranked[1], "https://medium.mirror/arch");
        assert_eq!(ranked[2], "https://slow.mirror/arch");
    }

    #[test]
    fn test_pactree_forward_traversal() {
        // Arrange
        let mut db = BTreeMap::new();
        db.insert("gtk4".to_string(), ArchPackageDesc {
            name: "gtk4".to_string(),
            depends: vec![AlpmDependency::parse("cairo"), AlpmDependency::parse("glib2")],
            ..Default::default()
        });
        db.insert("cairo".to_string(), ArchPackageDesc {
            name: "cairo".to_string(),
            depends: vec![AlpmDependency::parse("pixman")],
            ..Default::default()
        });
        db.insert("pixman".to_string(), ArchPackageDesc {
            name: "pixman".to_string(),
            depends: Vec::new(),
            ..Default::default()
        });

        // Act
        let tree = PacTree::dependency_tree("gtk4", &db);

        // Assert
        assert!(tree.contains_key("gtk4"));
        assert!(tree.contains_key("cairo"));
        assert!(tree.contains_key("pixman"));
    }

    #[test]
    fn test_arch_audit_vulnerability_matching() {
        // Arrange
        let mut scanner = ArchAuditScanner::new();
        scanner.add_advisory(SecurityAdvisory {
            advisory_id: "ASA-202403-1".to_string(),
            package: "xz".to_string(),
            cves: vec!["CVE-2024-3094".to_string()],
            severity: Severity::Critical,
            affected_lte: "5.6.1-1".to_string(),
            fixed_version: Some("5.6.1-2".to_string()),
        });

        let mut installed_vulnerable = BTreeMap::new();
        installed_vulnerable.insert("xz".to_string(), "5.6.1-1".to_string());

        let mut installed_fixed = BTreeMap::new();
        installed_fixed.insert("xz".to_string(), "5.6.1-2".to_string());

        // Act
        let reports_vuln = scanner.audit(&installed_vulnerable);
        let reports_fixed = scanner.audit(&installed_fixed);

        // Assert
        assert_eq!(reports_vuln.len(), 1);
        assert_eq!(reports_vuln[0].advisory_id, "ASA-202403-1");
        assert_eq!(reports_vuln[0].severity, Severity::Critical);

        assert!(reports_fixed.is_empty(), "fixed package must not be flagged");
    }

    #[test]
    fn test_namcap_linter_catches_fhs_and_license() {
        // Arrange
        let bad_pkg = ArchPackageDesc {
            name: "bad-package".to_string(),
            version: "1.0.0-1".to_string(),
            license: Vec::new(), // missing license
            url: "".to_string(), // missing url
            files: vec!["/usr/local/bin/test".to_string()], // FHS violation
            ..Default::default()
        };

        // Act
        let tags = NamcapLinter::lint(&bad_pkg);

        // Assert
        assert!(tags.iter().any(|t| t.tag_name == "missing-license"));
        assert!(tags.iter().any(|t| t.tag_name == "missing-url"));
        assert!(tags.iter().any(|t| t.tag_name == "fhs-local-violation"));
    }
}
