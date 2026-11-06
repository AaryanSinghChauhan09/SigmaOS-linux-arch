//! mkinitcpio modular initramfs creation and hook dependency resolver
//! Direct inspiration: https://github.com/archlinux/mkinitcpio

use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPhase {
    Early,
    Normal,
    Late,
    Cleanup,
}

#[derive(Debug, Clone)]
pub struct InitramfsHook {
    pub name: String,
    pub phase: HookPhase,
    pub dependencies: Vec<String>,
    pub provides: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MkinitcpioConfig {
    pub modules: Vec<String>,
    pub binaries: Vec<String>,
    pub files: Vec<String>,
    pub hooks: Vec<String>,
    pub compression: String,
}

impl Default for MkinitcpioConfig {
    fn default() -> Self {
        Self {
            modules: Vec::new(),
            binaries: Vec::new(),
            files: Vec::new(),
            hooks: vec![
                "base".to_string(),
                "udev".to_string(),
                "autodetect".to_string(),
                "modconf".to_string(),
                "block".to_string(),
                "filesystems".to_string(),
                "fsck".to_string(),
            ],
            compression: "zstd".to_string(),
        }
    }
}

impl MkinitcpioConfig {
    pub fn parse(content: &str) -> Self {
        let mut cfg = MkinitcpioConfig::default();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(pos) = trimmed.find('=') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos + 1..].trim();
                // strip quotes or parentheses
                let clean_val = val
                    .trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')');
                let items: Vec<String> = clean_val
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();

                match key {
                    "MODULES" => cfg.modules = items,
                    "BINARIES" => cfg.binaries = items,
                    "FILES" => cfg.files = items,
                    "HOOKS" => cfg.hooks = items,
                    "COMPRESSION" => cfg.compression = clean_val.to_string(),
                    _ => {}
                }
            }
        }

        cfg
    }
}

pub struct MkinitcpioHookSolver {
    pub available_hooks: BTreeMap<String, InitramfsHook>,
}

impl MkinitcpioHookSolver {
    pub fn standard() -> Self {
        let mut solver = Self {
            available_hooks: BTreeMap::new(),
        };

        solver.register(InitramfsHook {
            name: "base".to_string(),
            phase: HookPhase::Early,
            dependencies: Vec::new(),
            provides: vec!["busybox".to_string(), "init".to_string()],
        });

        solver.register(InitramfsHook {
            name: "udev".to_string(),
            phase: HookPhase::Early,
            dependencies: vec!["base".to_string()],
            provides: vec!["device-manager".to_string()],
        });

        solver.register(InitramfsHook {
            name: "autodetect".to_string(),
            phase: HookPhase::Normal,
            dependencies: vec!["base".to_string()],
            provides: Vec::new(),
        });

        solver.register(InitramfsHook {
            name: "modconf".to_string(),
            phase: HookPhase::Normal,
            dependencies: vec!["base".to_string()],
            provides: Vec::new(),
        });

        solver.register(InitramfsHook {
            name: "block".to_string(),
            phase: HookPhase::Normal,
            dependencies: vec!["udev".to_string()],
            provides: vec!["blockdev".to_string()],
        });

        solver.register(InitramfsHook {
            name: "encrypt".to_string(),
            phase: HookPhase::Normal,
            dependencies: vec!["block".to_string(), "udev".to_string()],
            provides: vec!["crypto-root".to_string()],
        });

        solver.register(InitramfsHook {
            name: "lvm2".to_string(),
            phase: HookPhase::Normal,
            dependencies: vec!["block".to_string(), "udev".to_string()],
            provides: vec!["lvm-root".to_string()],
        });

        solver.register(InitramfsHook {
            name: "filesystems".to_string(),
            phase: HookPhase::Late,
            dependencies: vec!["block".to_string()],
            provides: vec!["rootfs-mount".to_string()],
        });

        solver.register(InitramfsHook {
            name: "fsck".to_string(),
            phase: HookPhase::Late,
            dependencies: vec!["filesystems".to_string()],
            provides: Vec::new(),
        });

        solver
    }

    pub fn register(&mut self, hook: InitramfsHook) {
        self.available_hooks.insert(hook.name.clone(), hook);
    }

    /// Validate the hook list in configuration, ensuring all dependencies are satisfied
    /// in the correct chronological order.
    pub fn validate_and_order(&self, hooks: &[String]) -> Result<Vec<String>, String> {
        let mut provided = HashSet::new();
        let mut ordered = Vec::new();

        for name in hooks {
            let hook = self
                .available_hooks
                .get(name)
                .ok_or_else(|| format!("unknown hook: {}", name))?;

            // Check if all dependencies are satisfied by prior hooks
            for dep in &hook.dependencies {
                if !provided.contains(dep) && !hooks.iter().take_while(|h| *h != name).any(|h| h == dep) {
                    return Err(format!(
                        "hook '{}' missing required prior hook '{}'",
                        name, dep
                    ));
                }
            }

            provided.insert(name.clone());
            for p in &hook.provides {
                provided.insert(p.clone());
            }

            ordered.push(name.clone());
        }

        Ok(ordered)
    }

    /// Determine microcode early-initrd prepend for modern x86_64 CPU targets
    pub fn detect_microcode_prepend(&self, cpu_vendor: &str) -> Option<&'static str> {
        match cpu_vendor.to_lowercase().as_str() {
            "genuineintel" | "intel" => Some("boot/intel-ucode.img"),
            "authenticamd" | "amd" => Some("boot/amd-ucode.img"),
            _ => None,
        }
    }

    /// Generates early ramfs script structure
    pub fn generate_init_script(&self, ordered_hooks: &[String]) -> String {
        let mut script = String::new();
        script.push_str("#!/bin/sh\n");
        script.push_str("# Generated by SigmaOS mkinitcpio engine\n");
        script.push_str("echo ':: Mounting early virtual filesystems (/dev, /proc, /sys)...'\n");
        script.push_str("mount -t devtmpfs devtmpfs /dev\n");
        script.push_str("mount -t proc proc /proc\n");
        script.push_str("mount -t sysfs sysfs /sys\n\n");

        for hook in ordered_hooks {
            script.push_str(&format!("echo ':: Running early initramfs hook [{}]...'\n", hook));
            script.push_str(&format!("run_hook_{}\n", hook));
        }

        script.push_str("\necho ':: Pivoting to /new_root...'\n");
        script.push_str("exec switch_root /new_root /sbin/init\n");
        script
    }
}
