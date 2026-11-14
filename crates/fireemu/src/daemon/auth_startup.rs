//! Auth configuration phases owned by daemon startup.

use fireemu_core_auth::signup_quota::{
    QuotaAlgorithm, QuotaMode, SignupQuotaConfig, TemporaryQuota,
};
use fireemu_core_auth::store::{
    AuthNamespaceConfigPatch, AuthRegistry, AuthStore, ProjectAuthConfig, ProjectAuthConfigPatch,
};

use crate::config::RuntimeConfig;

/// Applies the declared settings to the initial Auth store in startup order.
pub(super) fn initialize_initial_store(
    cfg: &RuntimeConfig,
    store: &mut AuthStore,
) -> Result<(), String> {
    store.set_config(auth_project_config(cfg));
    store
        .set_sign_in_config(auth_sign_in_config(cfg))
        .map_err(|error| format!("auth.signIn: {error:?}"))?;
    if let Some(mfa) = cfg.effective_auth_mfa() {
        store.set_mfa_seed(mfa);
    }
    if let Some(domains) = &cfg.auth_authorized_domains {
        store
            .set_authorized_domains_seed(domains.clone())
            .map_err(|error| format!("auth.authorizedDomains: {error:?}"))?;
    }
    store
        .set_provider_config_seeds(cfg.auth_provider_seeds.clone())
        .map_err(|error| format!("auth.providers: {error}"))?;
    if let Some(policy) = &cfg.auth_password_policy {
        store.set_password_policy(policy.to_auth_policy());
    }
    store
        .set_signup_quota_config(auth_signup_quota_config(cfg)?)
        .map_err(|error| format!("auth.quotaSimulation: {error:?}"))?;
    Ok(())
}

/// Registers seeds and overrides for namespaces created after startup.
pub(super) fn initialize_registry(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    registry.set_new_project_mfa_seed(cfg.effective_auth_mfa());
    registry.set_new_project_authorized_domains_seed(cfg.auth_authorized_domains.clone());
    registry.set_new_project_provider_config_seeds(cfg.auth_provider_seeds.clone());
    apply_auth_password_policy_overrides(cfg, registry)?;
    apply_auth_config_overrides(cfg, registry)
}

/// Applies explicit root overrides, reports imported tenant collisions, then seeds declared tenants.
pub(super) fn apply_post_import(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
    mut report_shadowed_tenant: Option<impl FnMut(&str)>,
) -> Result<(), String> {
    reapply_explicit_auth_password_policies(cfg, registry)?;
    reapply_explicit_auth_config(cfg, registry)?;
    reapply_explicit_auth_quota(cfg, registry)?;

    let seeding = cfg.tenant_seeding()?;
    if let Some(report) = report_shadowed_tenant.as_mut() {
        for id in seeding.shadowed_by_existing(registry, &cfg.auth_project) {
            report(&id);
        }
    }
    seeding
        .apply(registry, &cfg.auth_project)
        .map_err(|error| format!("auth.tenants: {error}"))?;
    if !seeding.is_empty() {
        registry.set_new_project_tenant_seed(std::sync::Arc::new(seeding));
    }
    Ok(())
}

pub(super) fn apply_auth_password_policy_overrides(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    for (index, override_config) in cfg.auth_password_policy_overrides.iter().enumerate() {
        let policy = override_config.password_policy.to_auth_policy();
        let applied = match override_config.tenant_id.as_deref() {
            Some(tenant) => registry.register_tenant_password_policy_override(
                &override_config.project_id,
                tenant,
                policy,
            ),
            None => registry
                .register_project_password_policy_override(&override_config.project_id, policy),
        };
        if !applied {
            let namespace = override_config.tenant_id.as_deref().map_or_else(
                || override_config.project_id.clone(),
                |tenant| format!("{}/tenants/{tenant}", override_config.project_id),
            );
            return Err(format!(
                "cannot apply auth.passwordPolicyOverrides[{index}] to {namespace}"
            ));
        }
    }
    Ok(())
}

pub(super) fn auth_project_config(cfg: &RuntimeConfig) -> ProjectAuthConfig {
    ProjectAuthConfig {
        allow_duplicate_emails: cfg.auth_allow_duplicate_emails,
        enable_improved_email_privacy: cfg.auth_improved_email_privacy,
        disabled_user_signup: cfg.auth_client_permissions.disabled_user_signup,
        disabled_user_deletion: cfg.auth_client_permissions.disabled_user_deletion,
    }
}

pub(super) fn auth_sign_in_config(cfg: &RuntimeConfig) -> fireemu_core_auth::store::SignInConfig {
    let settings = &cfg.auth_sign_in;
    let mut config = fireemu_core_auth::store::SignInConfig::default();
    if let Some(value) = settings.email_enabled {
        config.email_enabled = value;
    }
    if let Some(value) = settings.password_required {
        config.password_required = value;
    }
    if let Some(value) = settings.anonymous_enabled {
        config.anonymous_enabled = value;
    }
    if let Some(value) = settings.phone_enabled {
        config.phone_enabled = value;
    }
    if let Some(numbers) = &settings.test_phone_numbers {
        config.test_phone_numbers.clone_from(numbers);
    }
    config
}

fn auth_namespace_config_patch(
    config: crate::config::AuthNamespaceConfig,
) -> AuthNamespaceConfigPatch {
    AuthNamespaceConfigPatch {
        allow_duplicate_emails: None,
        enable_improved_email_privacy: config.improved_email_privacy,
        disabled_user_signup: config
            .client_permissions
            .map(|permissions| permissions.disabled_user_signup),
        disabled_user_deletion: config
            .client_permissions
            .map(|permissions| permissions.disabled_user_deletion),
    }
}

pub(super) fn apply_auth_config_overrides(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    for (index, override_config) in cfg.auth_config_overrides.iter().enumerate() {
        let patch = auth_namespace_config_patch(override_config.config);
        if patch.is_empty() {
            continue;
        }
        let namespace = override_config.tenant_id.as_deref().map_or_else(
            || override_config.project_id.clone(),
            |tenant| format!("{}/tenants/{tenant}", override_config.project_id),
        );
        let applied = match override_config.tenant_id.as_deref() {
            Some(tenant) => {
                registry.register_tenant_config_override(&override_config.project_id, tenant, patch)
            }
            None => registry.register_project_config_override(&override_config.project_id, patch),
        };
        if !applied {
            return Err(format!(
                "cannot apply auth.configOverrides[{index}] to {namespace}"
            ));
        }
    }
    Ok(())
}

pub(super) fn reapply_explicit_auth_config(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    let patch = ProjectAuthConfigPatch {
        allow_duplicate_emails: cfg
            .auth_allow_duplicate_emails_explicit
            .then_some(cfg.auth_allow_duplicate_emails),
        enable_improved_email_privacy: cfg
            .auth_improved_email_privacy_explicit
            .then_some(cfg.auth_improved_email_privacy),
        disabled_user_signup: cfg
            .auth_client_permissions_explicit
            .then_some(cfg.auth_client_permissions.disabled_user_signup),
        disabled_user_deletion: cfg
            .auth_client_permissions_explicit
            .then_some(cfg.auth_client_permissions.disabled_user_deletion),
    };
    if !patch.is_empty()
        && registry
            .patch_project_config(&cfg.auth_project, patch)
            .is_none()
    {
        return Err(format!(
            "cannot apply explicit root Auth settings to {}",
            cfg.auth_project
        ));
    }
    apply_auth_config_overrides(cfg, registry)
}

pub(super) fn auth_signup_quota_config(cfg: &RuntimeConfig) -> Result<SignupQuotaConfig, String> {
    let mode = match cfg.auth_quota_simulation.mode {
        crate::config::AuthQuotaSimulationMode::Off => QuotaMode::Off,
        crate::config::AuthQuotaSimulationMode::Observe => QuotaMode::Observe,
        crate::config::AuthQuotaSimulationMode::Enforce => QuotaMode::Enforce,
    };
    let temporary = auth_temporary_quota_config(cfg)?;
    Ok(SignupQuotaConfig {
        mode,
        algorithm: QuotaAlgorithm::FixedWindowV1,
        default_quota_per_hour: cfg.auth_quota_simulation.default_quota_per_hour,
        max_tracked_buckets: cfg.auth_quota_simulation.max_tracked_buckets,
        temporary,
    })
}

fn auth_temporary_quota_config(cfg: &RuntimeConfig) -> Result<Option<TemporaryQuota>, String> {
    cfg.auth_signup_quota
        .as_ref()
        .map(|value| {
            let quota = value.quota.parse::<u64>().map_err(|_| {
                "auth.quota.signUpQuotaConfig.quota is not a valid uint64".to_owned()
            })?;
            TemporaryQuota::new(quota, value.start_time, value.quota_duration)
                .map_err(|error| format!("auth.quota.signUpQuotaConfig: {error:?}"))
        })
        .transpose()
}

pub(super) fn reapply_explicit_auth_password_policies(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    if let Some(policy) = &cfg.auth_password_policy {
        if !registry.set_project_password_policy(&cfg.auth_project, policy.to_auth_policy()) {
            return Err(format!(
                "cannot apply auth.passwordPolicy to {}",
                cfg.auth_project
            ));
        }
    }
    apply_auth_password_policy_overrides(cfg, registry)
}

pub(super) fn reapply_explicit_auth_quota(
    cfg: &RuntimeConfig,
    registry: &AuthRegistry,
) -> Result<(), String> {
    if !cfg.auth_signup_quota_explicit && !cfg.auth_quota_simulation_explicit {
        return Ok(());
    }
    let applied = registry
        .patch_project_config_with_current_settings(
            &cfg.auth_project,
            ProjectAuthConfigPatch::default(),
            |_, current| {
                let mut next = current.clone();
                if cfg.auth_signup_quota_explicit {
                    next.temporary = auth_temporary_quota_config(cfg)?;
                }
                if cfg.auth_quota_simulation_explicit {
                    next.mode = match cfg.auth_quota_simulation.mode {
                        crate::config::AuthQuotaSimulationMode::Off => QuotaMode::Off,
                        crate::config::AuthQuotaSimulationMode::Observe => QuotaMode::Observe,
                        crate::config::AuthQuotaSimulationMode::Enforce => QuotaMode::Enforce,
                    };
                    if cfg.auth_quota_simulation.algorithm != "fixed-window-v1" {
                        return Err("auth.quotaSimulation.algorithm is not supported".to_owned());
                    }
                    next.algorithm = QuotaAlgorithm::FixedWindowV1;
                    next.default_quota_per_hour = cfg.auth_quota_simulation.default_quota_per_hour;
                    next.max_tracked_buckets = cfg.auth_quota_simulation.max_tracked_buckets;
                }
                Ok((None, Some(next)))
            },
        )
        .map_err(|error| error.clone())?;
    if applied.is_none() {
        return Err(format!(
            "cannot apply explicit Auth quota settings to {}",
            cfg.auth_project
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "auth_startup_tests.rs"]
mod tests;
