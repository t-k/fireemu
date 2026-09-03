//! Canonical, path-independent Cargo dependency authority for Quint verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

const ROOT_PACKAGE: &str = "fireemu-verification-quint";
const TARGET: &str = "x86_64-unknown-linux-gnu";

/// Locked dependency graph that can affect the Quint verification crate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CargoAuthority {
    /// Authority schema version.
    pub schema_version: u32,
    /// Workspace package whose transitive graph is recorded.
    pub root_package: String,
    /// Cargo target used while resolving target-specific dependencies.
    pub target: String,
    /// Canonically ordered reachable packages.
    pub packages: Vec<AuthorityPackage>,
}

/// One reachable package and its resolved features and edges.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPackage {
    /// Repository-independent package identity.
    pub id: String,
    /// Cargo package name.
    pub name: String,
    /// Resolved package version.
    pub version: String,
    /// Registry or Git source for external packages.
    pub source: Option<String>,
    /// Repository-relative manifest for workspace packages.
    pub manifest: Option<String>,
    /// Enabled features for this resolved node.
    pub features: Vec<String>,
    /// Canonical identities of resolved normal dependencies.
    pub dependencies: Vec<String>,
}

/// Resolves the locked Quint dependency graph without accessing the network.
pub fn build_authority(repository_root: &Path) -> Result<CargoAuthority, String> {
    let repository_root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "cannot resolve repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(&repository_root)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            TARGET,
            "--format-version",
            "1",
        ])
        .output()
        .map_err(|error| format!("cannot launch cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    authority_from_metadata(&repository_root, &output.stdout)
}

/// Writes stable, newline-terminated authority JSON.
pub fn write_authority(repository_root: &Path, path: &Path) -> Result<(), String> {
    let authority = build_authority(repository_root)?;
    let mut json = serde_json::to_string_pretty(&authority)
        .map_err(|error| format!("cannot serialize Cargo authority: {error}"))?;
    json.push('\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create Cargo authority directory {}: {error}",
                parent.display()
            )
        })?;
    }
    fs::write(path, json)
        .map_err(|error| format!("cannot write Cargo authority {}: {error}", path.display()))
}

/// Verifies that a checked-in authority equals the current locked graph.
pub fn validate_authority_file(repository_root: &Path, path: &Path) -> Result<(), String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("cannot read Cargo authority {}: {error}", path.display()))?;
    let checked_in: CargoAuthority = serde_json::from_str(&json)
        .map_err(|error| format!("invalid Cargo authority {}: {error}", path.display()))?;
    let current = build_authority(repository_root)?;
    if checked_in == current {
        Ok(())
    } else {
        Err(format!(
            "Cargo authority is stale: {}; run verification/quint/run-verification.sh --refresh",
            path.display()
        ))
    }
}

fn authority_from_metadata(repository_root: &Path, bytes: &[u8]) -> Result<CargoAuthority, String> {
    let metadata: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))?;
    let package_values = metadata["packages"]
        .as_array()
        .ok_or_else(|| "cargo metadata has no packages array".to_owned())?;
    let node_values = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| "cargo metadata has no resolve nodes array".to_owned())?;

    let mut packages_by_raw_id = BTreeMap::new();
    let mut canonical_by_raw_id = BTreeMap::new();
    for package in package_values {
        let raw_id = string_field(package, "id")?;
        let canonical = canonical_id(repository_root, package)?;
        packages_by_raw_id.insert(raw_id.to_owned(), package);
        canonical_by_raw_id.insert(raw_id.to_owned(), canonical);
    }
    let nodes_by_raw_id = node_values
        .iter()
        .map(|node| Ok((string_field(node, "id")?.to_owned(), node)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let root_raw_id = package_values
        .iter()
        .find(|package| package["name"].as_str() == Some(ROOT_PACKAGE))
        .map(|package| string_field(package, "id"))
        .transpose()?
        .ok_or_else(|| format!("cargo metadata has no {ROOT_PACKAGE} package"))?;

    let mut reachable = BTreeSet::new();
    let mut pending = vec![root_raw_id.to_owned()];
    while let Some(raw_id) = pending.pop() {
        if !reachable.insert(raw_id.clone()) {
            continue;
        }
        let node = nodes_by_raw_id
            .get(&raw_id)
            .ok_or_else(|| format!("cargo metadata has no node for {raw_id}"))?;
        for dependency in normal_dependencies(node)? {
            pending.push(dependency);
        }
    }

    let mut packages = Vec::with_capacity(reachable.len());
    for raw_id in reachable {
        let package = packages_by_raw_id
            .get(&raw_id)
            .ok_or_else(|| format!("cargo metadata has no package for {raw_id}"))?;
        let node = nodes_by_raw_id
            .get(&raw_id)
            .ok_or_else(|| format!("cargo metadata has no node for {raw_id}"))?;
        let mut features = string_array(node, "features")?;
        features.sort();
        let mut dependencies = normal_dependencies(node)?
            .into_iter()
            .map(|dependency| {
                canonical_by_raw_id
                    .get(&dependency)
                    .cloned()
                    .ok_or_else(|| format!("cargo metadata has no package for {dependency}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        dependencies.sort();
        dependencies.dedup();
        let source = package["source"].as_str().map(str::to_owned);
        let manifest = if source.is_none() {
            Some(relative_manifest(repository_root, package)?)
        } else {
            None
        };
        packages.push(AuthorityPackage {
            id: canonical_by_raw_id[&raw_id].clone(),
            name: string_field(package, "name")?.to_owned(),
            version: string_field(package, "version")?.to_owned(),
            source,
            manifest,
            features,
            dependencies,
        });
    }
    packages.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(CargoAuthority {
        schema_version: 1,
        root_package: ROOT_PACKAGE.to_owned(),
        target: TARGET.to_owned(),
        packages,
    })
}

fn canonical_id(repository_root: &Path, package: &serde_json::Value) -> Result<String, String> {
    let name = string_field(package, "name")?;
    let version = string_field(package, "version")?;
    if let Some(source) = package["source"].as_str() {
        return Ok(format!("{source}#{name}@{version}"));
    }
    let manifest = relative_manifest(repository_root, package)?;
    Ok(format!("path+{manifest}#{name}@{version}"))
}

fn relative_manifest(
    repository_root: &Path,
    package: &serde_json::Value,
) -> Result<String, String> {
    let manifest = PathBuf::from(string_field(package, "manifest_path")?);
    let relative = manifest.strip_prefix(repository_root).map_err(|_| {
        format!(
            "workspace manifest {} is outside repository {}",
            manifest.display(),
            repository_root.display()
        )
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("cargo metadata field {field} is not a string"))
}

fn string_array(value: &serde_json::Value, field: &str) -> Result<Vec<String>, String> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("cargo metadata field {field} is not an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("cargo metadata field {field} contains a non-string"))
        })
        .collect()
}

fn normal_dependencies(node: &serde_json::Value) -> Result<Vec<String>, String> {
    node["deps"]
        .as_array()
        .ok_or_else(|| "cargo metadata node has no deps array".to_owned())?
        .iter()
        .filter(|dependency| {
            dependency["dep_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind["kind"].is_null()))
        })
        .map(|dependency| {
            dependency["pkg"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "cargo metadata dependency has no package id".to_owned())
        })
        .collect()
}
