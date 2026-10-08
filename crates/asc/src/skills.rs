//! Agent skill files compiled into this binary from the repository `skills/`
//! directory. `asc skills install` writes that snapshot into agent skill directories.

use std::fs;
use std::path::{Path, PathBuf};

use asc_apk::{Error, Result};

include!(concat!(env!("OUT_DIR"), "/skill_assets.rs"));

/// Skill directories `asc skills install` writes under the user home.
pub fn user_skill_dirs(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".grok/skills"),
        home.join(".agents/skills"),
        home.join(".claude/skills"),
        home.join(".cursor/skills"),
    ]
}

/// Writes every embedded skill under `skills_dir` and returns each skill root.
pub fn install_skills(skills_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for file in SKILL_FILES {
        let dest = skill_dest(skills_dir, file.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::IoPath {
                action: "create",
                path: parent.display().to_string(),
                source,
            })?;
        }
        fs::write(&dest, file.bytes).map_err(|source| Error::IoPath {
            action: "write",
            path: dest.display().to_string(),
            source,
        })?;
        let root = skill_root(skills_dir, file.path)?;
        if !roots.iter().any(|existing| existing == &root) {
            roots.push(root);
        }
    }
    Ok(roots)
}

fn skill_root(skills_dir: &Path, rel: &str) -> Result<PathBuf> {
    let name = rel
        .split('/')
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Error::new(format!("skill path {rel} has no directory")))?;
    skill_dest(skills_dir, name)
}

fn skill_dest(skills_dir: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(Error::new("skill path is empty"));
    }
    let mut dest = skills_dir.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::new(format!(
                "skill path {rel} escapes its directory"
            )));
        }
        dest.push(part);
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skills_install() {
        let root = std::env::temp_dir().join(format!("asc-skills-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let skills_dir = root.join("skills");
        let installed = install_skills(&skills_dir).unwrap();
        assert_eq!(installed, vec![skills_dir.join("asc")]);
        for file in SKILL_FILES {
            let written = fs::read(skills_dir.join(file.path)).unwrap();
            assert_eq!(written, file.bytes, "{}", file.path);
        }
        let _ = fs::remove_dir_all(&root);
    }
}
