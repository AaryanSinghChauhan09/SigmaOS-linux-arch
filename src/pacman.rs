//! Pacman & libalpm compatibility engine
//! Direct inspiration: https://github.com/archlinux/pacman

use std::collections::{BTreeMap, HashSet};
use std::fmt;

// =========================================================================
// 1. ALPM VERSION COMPARISON ENGINE (RFC: pacman/lib/libalpm/version.c)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmVersion {
    pub epoch: u32,
    pub pkgver: String,
    pub pkgrel: u32,
}

impl AlpmVersion {
    pub fn parse(s: &str) -> Self {
        let mut rest = s;
        let epoch = if let Some(colon) = rest.find(':') {
            let ep = rest[..colon].parse::<u32>().unwrap_or(0);
            rest = &rest[colon + 1..];
            ep
        } else {
            0
        };

        let pkgrel = if let Some(dash) = rest.rfind('-') {
            let rel = rest[dash + 1..].parse::<u32>().unwrap_or(1);
            rest = &rest[..dash];
            rel
        } else {
            1
        };

        Self {
            epoch,
            pkgver: rest.to_string(),
            pkgrel,
        }
    }

    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        if self.epoch != other.epoch {
            return self.epoch.cmp(&other.epoch);
        }

        let ver_cmp = compare_pkgver(&self.pkgver, &other.pkgver);
        if ver_cmp != std::cmp::Ordering::Equal {
            return ver_cmp;
        }

        self.pkgrel.cmp(&other.pkgrel)
    }
}

impl fmt::Display for AlpmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:{}-{}", self.epoch, self.pkgver, self.pkgrel)
        } else {
            write!(f, "{}-{}", self.pkgver, self.pkgrel)
        }
    }
}

fn compare_pkgver(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut ai = 0usize;
    let mut bi = 0usize;
    let ab = a.as_bytes();
    let bb = b.as_bytes();

    loop {
        while ai < ab.len() && (ab[ai] == b'.' || ab[ai] == b'_' || ab[ai] == b'+' || ab[ai] == b'-') {
            ai += 1;
        }
        while bi < bb.len() && (bb[bi] == b'.' || bb[bi] == b'_' || bb[bi] == b'+' || bb[bi] == b'-') {
            bi += 1;
        }

        if ai >= ab.len() && bi >= bb.len() {
            return Ordering::Equal;
        }
        if ai >= ab.len() {
            return Ordering::Less;
        }
        if bi >= bb.len() {
            return Ordering::Greater;
        }

        let a_is_digit = ab[ai].is_ascii_digit();
        let b_is_digit = bb[bi].is_ascii_digit();

        if a_is_digit && !b_is_digit {
            return Ordering::Greater;
        }
        if !a_is_digit && b_is_digit {
            return Ordering::Less;
        }

        if a_is_digit {
            let a_start = ai;
            while ai < ab.len() && ab[ai].is_ascii_digit() {
                ai += 1;
            }
            let b_start = bi;
            while bi < bb.len() && bb[bi].is_ascii_digit() {
                bi += 1;
            }
            let a_num: u64 = std::str::from_utf8(&ab[a_start..ai]).unwrap_or("0").parse().unwrap_or(0);
            let b_num: u64 = std::str::from_utf8(&bb[b_start..bi]).unwrap_or("0").parse().unwrap_or(0);
            let cmp = a_num.cmp(&b_num);
            if cmp != Ordering::Equal {
                return cmp;
            }
        } else {
            let a_start = ai;
            while ai < ab.len() && ab[ai].is_ascii_alphabetic() {
                ai += 1;
            }
            let b_start = bi;
            while bi < bb.len() && bb[bi].is_ascii_alphabetic() {
                bi += 1;
            }
            let cmp = ab[a_start..ai].cmp(&bb[b_start..bi]);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
    }
}

// =========================================================================
// 2. DEPENDENCY CONSTRAINT SPECIFICATION
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepOperator {
    Any,
    Equal,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmDependency {
    pub name: String,
    pub operator: DepOperator,
    pub version: Option<String>,
}

impl AlpmDependency {
    pub fn parse(spec: &str) -> Self {
        let trimmed = spec.trim();
        let ops = [
            (">=", DepOperator::GreaterOrEqual),
            ("<=", DepOperator::LessOrEqual),
            (">", DepOperator::Greater),
            ("<", DepOperator::Less),
            ("=", DepOperator::Equal),
        ];

        for (op_str, op) in ops {
            if let Some(pos) = trimmed.find(op_str) {
                let name = trimmed[..pos].trim().to_string();
                let ver = trimmed[pos + op_str.len()..].trim().to_string();
                return Self {
                    name,
                    operator: op,
                    version: Some(ver),
                };
            }
        }

        Self {
            name: trimmed.to_string(),
            operator: DepOperator::Any,
            version: None,
        }
    }

    pub fn is_satisfied_by(&self, pkg_name: &str, pkg_version: &str) -> bool {
        if self.name != pkg_name {
            return false;
        }

        let required_ver = match &self.version {
            Some(v) => v,
            None => return true,
        };

        let v_installed = AlpmVersion::parse(pkg_version);
        let v_required = AlpmVersion::parse(required_ver);
        let cmp = v_installed.compare(&v_required);

        match self.operator {
            DepOperator::Any => true,
            DepOperator::Equal => cmp == std::cmp::Ordering::Equal,
            DepOperator::Greater => cmp == std::cmp::Ordering::Greater,
            DepOperator::GreaterOrEqual => cmp != std::cmp::Ordering::Less,
            DepOperator::Less => cmp == std::cmp::Ordering::Less,
            DepOperator::LessOrEqual => cmp != std::cmp::Ordering::Greater,
        }
    }
}

// =========================================================================
// 3. ARCH SYNC DB & PKGINFO DESCRIPTOR
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchPackageDesc {
    pub name: String,
    pub version: String,
    pub base: Option<String>,
    pub desc: String,
    pub url: String,
    pub arch: String,
    pub build_date: u64,
    pub packager: String,
    pub size: u64,
    pub license: Vec<String>,
    pub depends: Vec<AlpmDependency>,
    pub optdepends: Vec<String>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub replaces: Vec<String>,
    pub files: Vec<String>,
}

impl ArchPackageDesc {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let mut pkg = ArchPackageDesc::default();
        let mut current_section = "";

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('%') && trimmed.ends_with('%') {
                current_section = trimmed;
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }

            match current_section {
                "%NAME%" => pkg.name = trimmed.to_string(),
                "%VERSION%" => pkg.version = trimmed.to_string(),
                "%BASE%" => pkg.base = Some(trimmed.to_string()),
                "%DESC%" => pkg.desc = trimmed.to_string(),
                "%URL%" => pkg.url = trimmed.to_string(),
                "%ARCH%" => pkg.arch = trimmed.to_string(),
                "%BUILDDATE%" => pkg.build_date = trimmed.parse().unwrap_or(0),
                "%PACKAGER%" => pkg.packager = trimmed.to_string(),
                "%SIZE%" | "%CSIZE%" | "%ISIZE%" => pkg.size = trimmed.parse().unwrap_or(0),
                "%LICENSE%" => pkg.license.push(trimmed.to_string()),
                "%DEPENDS%" => pkg.depends.push(AlpmDependency::parse(trimmed)),
                "%OPTDEPENDS%" => pkg.optdepends.push(trimmed.to_string()),
                "%CONFLICTS%" => pkg.conflicts.push(trimmed.to_string()),
                "%PROVIDES%" => pkg.provides.push(trimmed.to_string()),
                "%REPLACES%" => pkg.replaces.push(trimmed.to_string()),
                "%FILES%" => pkg.files.push(trimmed.to_string()),
                _ => {}
            }
        }

        if pkg.name.is_empty() {
            return Err("missing %NAME% in package description");
        }
        if pkg.version.is_empty() {
            return Err("missing %VERSION% in package description");
        }

        Ok(pkg)
    }
}

// =========================================================================
// 4. PACMAN CONFIGURATION PARSER (/etc/pacman.conf)
// =========================================================================

#[derive(Debug, Clone)]
pub struct PacmanRepo {
    pub name: String,
    pub servers: Vec<String>,
    pub sig_level: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PacmanConfig {
    pub root_dir: String,
    pub db_path: String,
    pub cache_dir: String,
    pub hook_dir: String,
    pub hold_pkgs: Vec<String>,
    pub ignore_pkgs: Vec<String>,
    pub architecture: String,
    pub parallel_downloads: u32,
    pub color: bool,
    pub check_space: bool,
    pub verbose_pkg_lists: bool,
    pub repositories: BTreeMap<String, PacmanRepo>,
}

impl Default for PacmanConfig {
    fn default() -> Self {
        Self {
            root_dir: "/".to_string(),
            db_path: "/var/lib/pacman".to_string(),
            cache_dir: "/var/cache/pacman/pkg".to_string(),
            hook_dir: "/etc/pacman.d/hooks".to_string(),
            hold_pkgs: vec!["pacman".to_string(), "glibc".to_string()],
            ignore_pkgs: Vec::new(),
            architecture: "auto".to_string(),
            parallel_downloads: 5,
            color: true,
            check_space: true,
            verbose_pkg_lists: true,
            repositories: BTreeMap::new(),
        }
    }
}

impl PacmanConfig {
    pub fn parse(content: &str) -> Self {
        let mut cfg = PacmanConfig::default();
        let mut current_section = "options".to_string();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                current_section = trimmed[1..trimmed.len() - 1].to_string();
                if current_section != "options" {
                    cfg.repositories
                        .entry(current_section.clone())
                        .or_insert_with(|| PacmanRepo {
                            name: current_section.clone(),
                            servers: Vec::new(),
                            sig_level: None,
                        });
                }
                continue;
            }

            let mut parts = trimmed.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();

            if current_section == "options" {
                match key {
                    "RootDir" => cfg.root_dir = val.to_string(),
                    "DBPath" => cfg.db_path = val.to_string(),
                    "CacheDir" => cfg.cache_dir = val.to_string(),
                    "HookDir" => cfg.hook_dir = val.to_string(),
                    "HoldPkg" => cfg.hold_pkgs = val.split_whitespace().map(|s| s.to_string()).collect(),
                    "IgnorePkg" => cfg.ignore_pkgs = val.split_whitespace().map(|s| s.to_string()).collect(),
                    "Architecture" => cfg.architecture = val.to_string(),
                    "ParallelDownloads" => cfg.parallel_downloads = val.parse().unwrap_or(5),
                    "Color" => cfg.color = true,
                    "CheckSpace" => cfg.check_space = true,
                    "VerbosePkgLists" => cfg.verbose_pkg_lists = true,
                    _ => {}
                }
            } else if let Some(repo) = cfg.repositories.get_mut(&current_section) {
                match key {
                    "Server" => repo.servers.push(val.to_string()),
                    "SigLevel" => repo.sig_level = Some(val.to_string()),
                    _ => {}
                }
            }
        }

        cfg
    }
}

// =========================================================================
// 5. ALPM TRANSACTION & DEPENDENCY RESOLUTION ENGINE
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionAction {
    Install(ArchPackageDesc),
    Upgrade {
        old_version: String,
        new_package: ArchPackageDesc,
    },
    Remove(String),
}

pub struct AlpmTransaction {
    pub actions: Vec<TransactionAction>,
    pub installed_db: BTreeMap<String, ArchPackageDesc>,
}

impl AlpmTransaction {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            installed_db: BTreeMap::new(),
        }
    }

    pub fn register_installed(&mut self, pkg: ArchPackageDesc) {
        self.installed_db.insert(pkg.name.clone(), pkg);
    }

    pub fn stage_install(&mut self, pkg: ArchPackageDesc) -> Result<(), String> {
        // Conflict check
        for conflict in &pkg.conflicts {
            if self.installed_db.contains_key(conflict) {
                return Err(format!("conflict detected: {} conflicts with installed {}", pkg.name, conflict));
            }
        }

        if let Some(existing) = self.installed_db.get(&pkg.name) {
            self.actions.push(TransactionAction::Upgrade {
                old_version: existing.version.clone(),
                new_package: pkg,
            });
        } else {
            self.actions.push(TransactionAction::Install(pkg));
        }
        Ok(())
    }

    pub fn stage_remove(&mut self, pkg_name: &str) -> Result<(), String> {
        if !self.installed_db.contains_key(pkg_name) {
            return Err(format!("target not found: {}", pkg_name));
        }
        // Check if anything depends on it
        for (installed_name, installed_pkg) in &self.installed_db {
            if installed_name == pkg_name {
                continue;
            }
            for dep in &installed_pkg.depends {
                if dep.name == pkg_name {
                    return Err(format!(
                        "cannot remove {}: required by {}",
                        pkg_name, installed_name
                    ));
                }
            }
        }
        self.actions.push(TransactionAction::Remove(pkg_name.to_string()));
        Ok(())
    }

    /// Resolve topological ordering for safe sequential installation
    pub fn resolve_order(&self) -> Vec<String> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();

        for action in &self.actions {
            if let TransactionAction::Install(pkg) | TransactionAction::Upgrade { new_package: pkg, .. } = action {
                self.visit_deps(pkg, &mut visited, &mut order);
            }
        }

        order
    }

    fn visit_deps(&self, pkg: &ArchPackageDesc, visited: &mut HashSet<String>, order: &mut Vec<String>) {
        if visited.contains(&pkg.name) {
            return;
        }
        visited.insert(pkg.name.clone());

        for dep in &pkg.depends {
            if let Some(dep_pkg) = self.installed_db.get(&dep.name) {
                self.visit_deps(dep_pkg, visited, order);
            }
        }

        order.push(pkg.name.clone());
    }
}
