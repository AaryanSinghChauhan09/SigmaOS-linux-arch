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
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut deps = Vec::new();

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
                "%NAME%" => name = Some(trimmed.to_string()),
                "%VERSION%" => version = Some(trimmed.to_string()),
                "%ARCH%" => arch = Some(trimmed.to_string()),
                "%DEPENDS%" => deps.push(trimmed.to_string()),
                _ => {}
            }
        }

        Some(ArchPackageMeta {
            name: name?,
            version: version?,
            architecture: arch.unwrap_or_else(|| "x86_64".to_string()),
            dependencies: deps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
