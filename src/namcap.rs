//! namcap package analysis and linting engine
//! Direct inspiration: https://github.com/archlinux/namcap

use crate::pacman::ArchPackageDesc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagLevel {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintTag {
    pub level: TagLevel,
    pub tag_name: &'static str,
    pub message: String,
}

pub struct NamcapLinter;

impl NamcapLinter {
    /// Analyze package metadata and file manifest for common packaging mistakes
    pub fn lint(pkg: &ArchPackageDesc) -> Vec<LintTag> {
        let mut tags = Vec::new();

        // Rule 1: License declaration
        if pkg.license.is_empty() {
            tags.push(LintTag {
                level: TagLevel::Error,
                tag_name: "missing-license",
                message: "Package does not specify any license in metadata".to_string(),
            });
        }

        // Rule 2: Upstream URL
        if pkg.url.is_empty() {
            tags.push(LintTag {
                level: TagLevel::Warning,
                tag_name: "missing-url",
                message: "Package does not declare an upstream URL".to_string(),
            });
        }

        // Rule 3: FHS compliance checks on file paths
        for file in &pkg.files {
            if file.starts_with("/usr/local") || file.starts_with("usr/local") {
                tags.push(LintTag {
                    level: TagLevel::Error,
                    tag_name: "fhs-local-violation",
                    message: format!("Package contains file in /usr/local: {}", file),
                });
            }
            if file.starts_with("/opt/") && !file.starts_with("/opt/sigma") {
                tags.push(LintTag {
                    level: TagLevel::Warning,
                    tag_name: "opt-placement",
                    message: format!("Package places non-system files in /opt: {}", file),
                });
            }
        }

        // Rule 4: Self-dependency check
        for dep in &pkg.depends {
            if dep.name == pkg.name {
                tags.push(LintTag {
                    level: TagLevel::Error,
                    tag_name: "circular-self-dependency",
                    message: format!("Package declares dependency on itself: {}", pkg.name),
                });
            }
        }

        tags
    }
}
