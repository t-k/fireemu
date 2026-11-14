use super::*;

#[test]
fn pict_policy_rows_run_against_real_auth_store_and_registry() {
    let rows = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/auth_startup_policy.tsv"),
    )
    .expect("read startup policy fixture");
    for (line, row) in rows.lines().enumerate().skip(1) {
        let fields = row.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5, "row {}: {row}", line + 1);
        let [phase, root_setting, namespace, tenant_state, imported_value] = fields.as_slice()
        else {
            unreachable!("checked field count")
        };
        let mut auth = serde_json::json!({});
        if *root_setting == "Explicit" {
            auth["signIn"] = serde_json::json!({"allowDuplicateEmails": *phase == "Initial"});
        }
        if *tenant_state != "NoTenant" {
            auth["multiTenant"] = serde_json::json!({"allowTenants": true});
            auth["tenants"] = serde_json::json!([{
                "tenantId": "tenant-a",
                "displayName": "declared",
                "allowPasswordSignup": false
            }]);
        }
        auth["configOverrides"] = serde_json::json!([{
            "projectId": "future-project",
            "config": {"improvedEmailPrivacy": false}
        }]);
        let cfg = RuntimeConfig::from_json(&serde_json::json!({
            "schemaVersion": 1,
            "auth": auth
        }))
        .expect("valid table-driven startup config");
        let imported_config = *imported_value == "Conflicting";
        let default_store = std::sync::Arc::new(std::sync::Mutex::new(AuthStore::new(
            "demo-app",
            fireemu_core_types::determinism::SplitMix64::new(42),
            fireemu_core_auth::mfa::TotpPolicy::default(),
        )));
        let registry = AuthRegistry::new("demo-app", default_store.clone());
        if *namespace == "Existing" {
            assert!(registry.register(
                "future-project",
                AuthStore::new(
                    "future-project",
                    fireemu_core_types::determinism::SplitMix64::new(43),
                    fireemu_core_auth::mfa::TotpPolicy::default(),
                ),
            ));
        }

        if *phase == "Initial" {
            initialize_initial_store(&cfg, &mut default_store.lock().unwrap())
                .expect("initial store phase");
            assert_eq!(
                default_store
                    .lock()
                    .unwrap()
                    .config()
                    .allow_duplicate_emails,
                *root_setting == "Explicit",
                "row {}: {row}",
                line + 1
            );
            continue;
        }

        default_store.lock().unwrap().set_config(ProjectAuthConfig {
            allow_duplicate_emails: imported_config,
            ..ProjectAuthConfig::default()
        });
        initialize_registry(&cfg, &registry).expect("registry phase");
        let imported_tenant = if *tenant_state == "ImportedSameId" {
            let tenant = registry.ensure_tenant("demo-app", "tenant-a").unwrap();
            assert!(registry.update_tenant(
                "demo-app",
                "tenant-a",
                fireemu_core_auth::store::TenantMetadata {
                    display_name: Some("imported".to_owned()),
                    allow_password_signup: true,
                    ..Default::default()
                }
            ));
            Some(tenant)
        } else {
            None
        };
        let mut reported = Vec::new();
        apply_post_import(
            &cfg,
            &registry,
            Some(|id: &str| reported.push(id.to_owned())),
        )
        .expect("post-import phase");
        let expected_root = if *root_setting == "Explicit" {
            false
        } else {
            imported_config
        };
        assert_eq!(
            default_store
                .lock()
                .unwrap()
                .config()
                .allow_duplicate_emails,
            expected_root,
            "row {}: {row}",
            line + 1
        );
        if *namespace == "Absent" {
            assert!(registry.store_for("future-project").is_none(), "row: {row}");
        } else {
            assert!(
                !registry
                    .store_for("future-project")
                    .unwrap()
                    .lock()
                    .unwrap()
                    .config()
                    .enable_improved_email_privacy,
                "row: {row}"
            );
        }
        if *tenant_state == "ImportedSameId" {
            assert_eq!(reported, ["tenant-a"], "row: {row}");
            assert!(std::sync::Arc::ptr_eq(
                &imported_tenant.unwrap(),
                &registry
                    .tenant_store("demo-app", "tenant-a")
                    .expect("imported tenant remains registered")
            ));
            let metadata = registry.tenant_metadata("demo-app", "tenant-a").unwrap();
            assert_eq!(metadata.display_name.as_deref(), Some("imported"));
            assert!(metadata.allow_password_signup);
        } else if *tenant_state == "DeclaredOnly" {
            assert!(reported.is_empty(), "row: {row}");
            let metadata = registry.tenant_metadata("demo-app", "tenant-a").unwrap();
            assert_eq!(metadata.display_name.as_deref(), Some("declared"));
            assert!(!metadata.allow_password_signup);
        }
    }
}
