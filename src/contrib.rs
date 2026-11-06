//! pacman-contrib utilities suite (paccache, checkupdates, rankmirrors, pactree)
//! Direct inspiration: https://github.com/archlinux/pacman-contrib

use std::collections::{BTreeMap, HashSet};
use crate::pacman::{AlpmVersion, ArchPackageDesc};

// =========================================================================
// 1. PACCACHE (Package Cache Cleaner)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedPackageFile {
    pub pkgname: String,
    pub version: String,
    pub arch: String,
    pub filename: String,
    pub size_bytes: u64,
}

pub struct PacCache {
    pub keep_versions: usize,
    pub cached_files: Vec<CachedPackageFile>,
}

impl PacCache {
    pub fn new(keep_versions: usize) -> Self {
        Self {
            keep_versions,
            cached_files: Vec::new(),
        }
    }

    pub fn add_file(&mut self, file: CachedPackageFile) {
        self.cached_files.push(file);
    }

    /// Identify candidate files to remove based on keep_versions retention policy
    pub fn scan_candidates_for_removal(&self) -> Vec<CachedPackageFile> {
        let mut grouped: BTreeMap<String, Vec<&CachedPackageFile>> = BTreeMap::new();
        for file in &self.cached_files {
            grouped.entry(file.pkgname.clone()).or_default().push(file);
        }

        let mut to_remove = Vec::new();
        for (_pkgname, mut files) in grouped {
            if files.len() <= self.keep_versions {
                continue;
            }

            // Sort newest version to oldest version
            files.sort_by(|a, b| {
                let va = AlpmVersion::parse(&a.version);
                let vb = AlpmVersion::parse(&b.version);
                vb.compare(&va) // descending
            });

            // Keep the first `keep_versions`, rest are removal candidates
            for file in &files[self.keep_versions..] {
                to_remove.push((*file).clone());
            }
        }

        to_remove
    }
}

// =========================================================================
// 2. CHECKUPDATES (Safe Non-Destructive Update Checker)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpdate {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
}

pub struct CheckUpdates;

impl CheckUpdates {
    /// Compares installed packages with available packages in sync repository
    pub fn find_updates(
        installed: &BTreeMap<String, String>,
        sync_db: &BTreeMap<String, String>,
    ) -> Vec<PendingUpdate> {
        let mut updates = Vec::new();

        for (pkgname, installed_ver) in installed {
            if let Some(sync_ver) = sync_db.get(pkgname) {
                let v_inst = AlpmVersion::parse(installed_ver);
                let v_sync = AlpmVersion::parse(sync_ver);
                if v_sync.compare(&v_inst) == std::cmp::Ordering::Greater {
                    updates.push(PendingUpdate {
                        name: pkgname.clone(),
                        old_version: installed_ver.clone(),
                        new_version: sync_ver.clone(),
                    });
                }
            }
        }

        updates
    }
}

// =========================================================================
// 3. RANKMIRRORS (Mirror Benchmark & Ranking)
// =========================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct MirrorEntry {
    pub url: String,
    pub latency_ms: u64,
    pub reachable: bool,
}

pub struct RankMirrors;

impl RankMirrors {
    /// Sort mirrors by lowest latency, discarding unreachable mirrors
    pub fn rank(mirrors: &[MirrorEntry]) -> Vec<String> {
        let mut reachable: Vec<&MirrorEntry> = mirrors.iter().filter(|m| m.reachable).collect();
        reachable.sort_by_key(|m| m.latency_ms);
        reachable.into_iter().map(|m| m.url.clone()).collect()
    }
}

// =========================================================================
// 4. PACTREE (Package Dependency Tree)
// =========================================================================

pub struct PacTree;

impl PacTree {
    /// Build forward dependency tree starting at target package
    pub fn dependency_tree(
        target: &str,
        db: &BTreeMap<String, ArchPackageDesc>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut tree = BTreeMap::new();
        let mut visited = HashSet::new();
        Self::traverse(target, db, &mut tree, &mut visited);
        tree
    }

    fn traverse(
        current: &str,
        db: &BTreeMap<String, ArchPackageDesc>,
        tree: &mut BTreeMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
    ) {
        if visited.contains(current) {
            return;
        }
        visited.insert(current.to_string());

        if let Some(pkg) = db.get(current) {
            let deps: Vec<String> = pkg.depends.iter().map(|d| d.name.clone()).collect();
            tree.insert(current.to_string(), deps.clone());
            for dep in deps {
                Self::traverse(&dep, db, tree, visited);
            }
        }
    }
}
