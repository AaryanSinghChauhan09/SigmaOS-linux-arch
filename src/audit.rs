//! arch-audit Arch Security Advisory (ASA) CVE vulnerability scanner engine
//! Direct inspiration: https://github.com/archlinux/arch-audit

use std::collections::BTreeMap;
use crate::pacman::AlpmVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAdvisory {
    pub advisory_id: String,
    pub package: String,
    pub cves: Vec<String>,
    pub severity: Severity,
    pub affected_lte: String,
    pub fixed_version: Option<String>,
}

pub struct ArchAuditScanner {
    pub advisories: Vec<SecurityAdvisory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityReport {
    pub advisory_id: String,
    pub package: String,
    pub installed_version: String,
    pub severity: Severity,
    pub cves: Vec<String>,
    pub fixed_version: Option<String>,
}

impl ArchAuditScanner {
    pub fn new() -> Self {
        Self {
            advisories: Vec::new(),
        }
    }

    pub fn add_advisory(&mut self, adv: SecurityAdvisory) {
        self.advisories.push(adv);
    }

    /// Audit a collection of installed packages (pkgname -> version)
    pub fn audit(&self, installed: &BTreeMap<String, String>) -> Vec<VulnerabilityReport> {
        let mut reports = Vec::new();

        for adv in &self.advisories {
            if let Some(installed_ver) = installed.get(&adv.package) {
                let v_inst = AlpmVersion::parse(installed_ver);
                let v_aff = AlpmVersion::parse(&adv.affected_lte);

                // If installed version <= affected_lte, check if it has been fixed
                if v_inst.compare(&v_aff) != std::cmp::Ordering::Greater {
                    let is_vulnerable = match &adv.fixed_version {
                        Some(fix_ver) => {
                            let v_fix = AlpmVersion::parse(fix_ver);
                            v_inst.compare(&v_fix) == std::cmp::Ordering::Less
                        }
                        None => true, // unpatched / 0-day
                    };

                    if is_vulnerable {
                        reports.push(VulnerabilityReport {
                            advisory_id: adv.advisory_id.clone(),
                            package: adv.package.clone(),
                            installed_version: installed_ver.clone(),
                            severity: adv.severity,
                            cves: adv.cves.clone(),
                            fixed_version: adv.fixed_version.clone(),
                        });
                    }
                }
            }
        }

        reports
    }
}
