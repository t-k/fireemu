//! Source-owned lexical scope plans without request bindings or self references.
//! Declaration lookups check live structural paths and ancestry; a miss rebuilds the request's plan once. Names, order, bodies and match captures always come from the borrowed AST.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ast::{FunctionDecl, Item};

#[cfg(test)]
std::thread_local! { pub(crate) static PLAN_BUILDS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }

#[cfg(test)]
std::thread_local! {
    pub(crate) static BUILD_OBSERVER: core::cell::RefCell<Option<Arc<std::sync::atomic::AtomicUsize>>> = const { core::cell::RefCell::new(None) };
}

/// Keeps test observations independent while allowing a parser or evaluator child thread to
/// report to the observation that explicitly admitted it.
#[cfg(test)]
pub(crate) struct BuildObservation(Option<Arc<std::sync::atomic::AtomicUsize>>);

#[cfg(test)]
impl BuildObservation {
    pub(crate) fn enter(observer: Option<Arc<std::sync::atomic::AtomicUsize>>) -> Self {
        Self(BUILD_OBSERVER.with(|active| active.replace(observer)))
    }
}

#[cfg(test)]
impl Drop for BuildObservation {
    fn drop(&mut self) {
        BUILD_OBSERVER.with(|active| active.replace(self.0.take()));
    }
}

#[cfg(test)]
std::thread_local! { pub(crate) static LEGACY_EVALUATION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) }; }

#[cfg(test)]
std::thread_local! {
    /// Counts `ServiceScopes::agrees` walks started by `FunctionScopes`.
    pub(crate) static AGREEMENT_CHECKS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
std::thread_local! {
    /// Restores the pre-lazy per-request setup (agreement walk and capture tables for every
    /// entered block) so differential tests can compare it with the lazy path.
    pub(crate) static EAGER_SCOPE_SETUP: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Function(usize),
    Match(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Block {
    parent: Option<usize>,
    path: Vec<usize>,
    shape: Vec<Shape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceScopes {
    blocks: Vec<Block>,
    declarations: BTreeMap<usize, Vec<(usize, usize)>>,
}

impl ServiceScopes {
    pub(crate) fn compile(items: &[Item]) -> Arc<Self> {
        #[cfg(test)]
        PLAN_BUILDS.with(|work| work.set(work.get() + 1));
        #[cfg(test)]
        BUILD_OBSERVER.with(|observer| {
            if let Some(observer) = observer.borrow().as_ref() {
                observer.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let mut plan = Self {
            blocks: Vec::new(),
            declarations: BTreeMap::new(),
        };
        plan.block(items, None, Vec::new());
        Arc::new(plan)
    }

    fn block(&mut self, items: &[Item], parent: Option<usize>, path: Vec<usize>) -> usize {
        let id = self.blocks.len();
        self.blocks.push(Block {
            parent,
            path: Vec::new(),
            shape: Vec::new(),
        });
        let mut shape = Vec::with_capacity(items.len());
        for (position, item) in items.iter().enumerate() {
            shape.push(match item {
                Item::Function(function) => {
                    self.declarations
                        .entry(function.span.offset)
                        .or_default()
                        .push((id, position));
                    Shape::Function(function.span.offset)
                }
                Item::Match(block) => {
                    let mut child = path.clone();
                    child.push(position);
                    Shape::Match(self.block(&block.items, Some(id), child))
                }
            });
        }
        self.blocks[id].shape = shape;
        self.blocks[id].path = path;
        id
    }

    #[cfg(test)]
    fn agrees(&self, items: &[Item], block: usize) -> bool {
        let shape = &self.blocks[block].shape;
        items.len() == shape.len()
            && items
                .iter()
                .zip(shape)
                .all(|(item, shape)| match (item, shape) {
                    (Item::Function(function), Shape::Function(offset)) => {
                        function.span.offset == *offset
                    }
                    (Item::Match(block), Shape::Match(id)) => self.agrees(&block.items, *id),
                    _ => false,
                })
    }

    fn items<'a>(&self, root: &'a [Item], block: usize) -> Option<&'a [Item]> {
        let mut items = root;
        for &position in &self.blocks.get(block)?.path {
            let Item::Match(block) = items.get(position)? else {
                return None;
            };
            items = &block.items;
        }
        Some(items)
    }

    /// Every parent must describe the actual live structural prefix of this declaration.
    /// Names and declaration order are read from those live blocks during lookup.
    fn ancestry_agrees(&self, root: &[Item], mut scope: usize) -> bool {
        let Some(target) = self.blocks.get(scope) else {
            return false;
        };
        let mut depth = target.path.len();
        loop {
            let Some(block) = self.blocks.get(scope) else {
                return false;
            };
            if block.path != target.path[..depth] || self.items(root, scope).is_none() {
                return false;
            }
            if depth == 0 {
                return block.parent.is_none();
            }
            let Some(parent_id) = block.parent else {
                return false;
            };
            let Some(parent) = self.blocks.get(parent_id) else {
                return false;
            };
            if parent.path != target.path[..depth - 1]
                || parent.shape.get(target.path[depth - 1]) != Some(&Shape::Match(scope))
            {
                return false;
            }
            scope = parent_id;
            depth -= 1;
        }
    }

    fn scope_for(&self, root: &[Item], function: &FunctionDecl) -> Option<usize> {
        self.declarations
            .get(&function.span.offset)?
            .iter()
            .find_map(|&(scope, position)| {
                let Item::Function(found) = self.items(root, scope)?.get(position)? else {
                    return None;
                };
                (std::ptr::eq(found, function)
                    && self.blocks.get(scope)?.shape.get(position)
                        == Some(&Shape::Function(function.span.offset))
                    && self.ancestry_agrees(root, scope))
                .then_some(scope)
            })
    }
}

pub(crate) struct FunctionScopes<'a> {
    items: &'a [Item],
    compiled: &'a Arc<ServiceScopes>,
    /// Rebuilt at most once when a live declaration cannot use the generation's paths.
    /// The immutable borrow keeps previously validated environments valid after fallback.
    plan: OnceCell<Arc<ServiceScopes>>,
    #[cfg(test)]
    legacy: Option<BTreeMap<usize, Arc<crate::eval::LegacyFunctionEnvironment<'a>>>>,
}

impl<'a> FunctionScopes<'a> {
    pub(crate) fn new(items: &'a [Item], compiled: &'a Arc<ServiceScopes>) -> Self {
        let scopes = Self {
            items,
            compiled,
            plan: OnceCell::new(),
            #[cfg(test)]
            legacy: LEGACY_EVALUATION.with(core::cell::Cell::get).then(|| {
                let mut scopes = BTreeMap::new();
                crate::eval::collect_function_scopes(items, None, &mut scopes);
                scopes
            }),
        };
        #[cfg(test)]
        if EAGER_SCOPE_SETUP.with(core::cell::Cell::get) {
            scopes.plan();
        }
        scopes
    }

    /// The compiled plan when it still describes `items`; otherwise a plan rebuilt from them.
    #[cfg(test)]
    pub(crate) fn plan(&self) -> &Arc<ServiceScopes> {
        self.plan.get_or_init(|| {
            #[cfg(test)]
            AGREEMENT_CHECKS.with(|checks| checks.set(checks.get() + 1));
            if self.compiled.agrees(self.items, 0) {
                Arc::clone(self.compiled)
            } else {
                ServiceScopes::compile(self.items)
            }
        })
    }

    pub(crate) fn get(&self, function: &FunctionDecl) -> Option<FunctionEnvironment<'a>> {
        #[cfg(test)]
        if let Some(legacy) = &self.legacy {
            return legacy
                .get(&(std::ptr::from_ref(function) as usize))
                .map(|environment| FunctionEnvironment {
                    items: self.items,
                    plan: Arc::clone(self.plan()),
                    scope: 0,
                    legacy: Some(Arc::clone(environment)),
                });
        }
        let (plan, scope) = if let Some(plan) = self.plan.get() {
            (plan, plan.scope_for(self.items, function)?)
        } else if let Some(scope) = self.compiled.scope_for(self.items, function) {
            (self.compiled, scope)
        } else {
            let plan = self.plan.get_or_init(|| ServiceScopes::compile(self.items));
            (plan, plan.scope_for(self.items, function)?)
        };
        Some(FunctionEnvironment {
            items: self.items,
            plan: Arc::clone(plan),
            scope,
            #[cfg(test)]
            legacy: None,
        })
    }
}

#[derive(Clone)]
pub(crate) struct FunctionEnvironment<'a> {
    items: &'a [Item],
    plan: Arc<ServiceScopes>,
    scope: usize,
    #[cfg(test)]
    legacy: Option<Arc<crate::eval::LegacyFunctionEnvironment<'a>>>,
}

impl<'a> FunctionEnvironment<'a> {
    pub(crate) fn function(&self, name: &str) -> Option<&'a FunctionDecl> {
        #[cfg(test)]
        if let Some(legacy) = &self.legacy {
            let mut environment = Some(legacy.as_ref());
            while let Some(current) = environment {
                if let Some(function) = current
                    .own
                    .iter()
                    .rev()
                    .find(|function| function.name == name)
                {
                    return Some(function);
                }
                environment = current.parent.as_deref();
            }
            return None;
        }
        let mut scope = Some(self.scope);
        while let Some(id) = scope {
            if let Some(function) = self
                .plan
                .items(self.items, id)?
                .iter()
                .rev()
                .find_map(|item| match item {
                    Item::Function(function) if function.name == name => Some(function),
                    _ => None,
                })
            {
                return Some(function);
            }
            scope = self.plan.blocks[id].parent;
        }
        None
    }
}

#[cfg(test)]
pub(crate) fn measurement_iterations(mut operation: impl FnMut()) -> u32 {
    let mut iterations = 1_024;
    loop {
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            operation();
        }
        if started.elapsed() >= std::time::Duration::from_millis(200) || iterations >= 1_048_576 {
            return iterations;
        }
        iterations *= 2;
    }
}

#[cfg(test)]
pub(crate) fn measurement_sample(
    label: &str,
    sample: u32,
    iterations: u32,
    mut operation: impl FnMut(),
) {
    let started = std::time::Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed();
    println!(
        "scope-measure {label} sample={sample} iterations={iterations} elapsed_ns={} mean={:?}",
        elapsed.as_nanos(),
        elapsed / iterations
    );
}

#[cfg(test)]
fn measure_operation(label: &str, mut operation: impl FnMut()) {
    let iterations = measurement_iterations(&mut operation);
    for sample in 0..5 {
        measurement_sample(label, sample, iterations, &mut operation);
    }
}

#[cfg(test)]
mod scope_plan_tests {
    #[test]
    fn access_local_scope_lookup_handles_later_declarations_and_duplicate_offsets() {
        let mut tree = crate::parse::parse_ruleset(
            "service cloud.firestore { function original() { return true; } }",
        )
        .unwrap();
        let crate::ast::Item::Function(original) = &tree.services[0].items[0] else {
            unreachable!()
        };
        let mut added = original.clone();
        added.name = "added".into();
        tree.services[0]
            .items
            .push(crate::ast::Item::Function(added));
        let crate::ast::Item::Function(original) = &tree.services[0].items[0] else {
            unreachable!()
        };
        let crate::ast::Item::Function(added) = &tree.services[0].items[1] else {
            unreachable!()
        };
        let foreign = added.clone();
        super::PLAN_BUILDS.with(|count| count.set(0));
        let scopes = super::FunctionScopes::new(&tree.services[0].items, &tree.function_scopes[0]);
        let first = scopes.get(original).unwrap();
        assert!(std::ptr::eq(first.function("added").unwrap(), added));
        let second = scopes.get(added).unwrap();
        assert!(std::ptr::eq(second.function("original").unwrap(), original));
        assert!(scopes.get(original).is_some());
        assert!(scopes.get(&foreign).is_none());
        assert_eq!(
            super::PLAN_BUILDS.with(core::cell::Cell::get),
            1,
            "one fallback for the evaluation, not one per lookup"
        );
    }

    #[test]
    fn access_local_scope_lookup_handles_truncated_paths_without_leaking_ancestors() {
        let mut tree = crate::parse::parse_ruleset("service cloud.firestore { function ancestor() { return true; } match /old { function moved() { return ancestor(); } } }").unwrap();
        let crate::ast::Item::Match(old) = &tree.services[0].items[1] else {
            unreachable!()
        };
        let moved = old.items[0].clone();
        tree.services[0].items = vec![moved];
        let crate::ast::Item::Function(moved) = &tree.services[0].items[0] else {
            unreachable!()
        };
        let foreign = moved.clone();
        let scopes = super::FunctionScopes::new(&tree.services[0].items, &tree.function_scopes[0]);
        let environment = scopes.get(moved).unwrap();
        assert!(std::ptr::eq(environment.function("moved").unwrap(), moved));
        assert!(environment.function("ancestor").is_none());
        assert!(scopes.get(&foreign).is_none());
    }

    #[test]
    #[ignore = "bounded release measurement; compilation and parsing are outside timed loops"]
    fn measure_residual_scope_resolution() {
        use crate::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
        use std::fmt::Write as _;
        use std::hint::black_box;

        let request = RequestContext {
            service: RulesService::Firestore,
            method: Method::Get,
            path: "/databases/(default)/documents/notes/one".to_owned(),
            auth: None,
            resource: None,
            request_resource: None,
            time_unix_nanos: 0,
            abstract_path: false,
            request_query: None,
        };
        for condition in ["true", "inner()"] {
            for unrelated in [0, 100, 1_000] {
                let mut source = format!(
                    "rules_version = '2'; service cloud.firestore {{ function top() {{ return true; }} match /databases/{{db}}/documents {{ function inner() {{ return top(); }} match /notes/{{id}} {{ allow get: if {condition}; }}"
                );
                for index in 0..unrelated {
                    let _ = write!(
                        source,
                        " match /unrelated{index}/{{id}} {{ function helper{index}() {{ return id == 'x'; }} allow get: if helper{index}(); }}"
                    );
                }
                source.push_str(" } }");
                let tree = crate::parse::parse_ruleset(&source).unwrap();
                assert_eq!(evaluate_request(&tree, &request).decision, Decision::Allow);
                let items = &tree.services[0].items;
                let compiled = &tree.function_scopes[0];
                let label = format!("condition={condition} blocks={unrelated}");
                super::measure_operation(&format!("{label} full"), || {
                    black_box(evaluate_request(black_box(&tree), black_box(&request)));
                });
                super::measure_operation(&format!("{label} first-plan"), || {
                    let scopes = super::FunctionScopes::new(black_box(items), black_box(compiled));
                    black_box(scopes.plan());
                });
                super::measure_operation(&format!("{label} agrees"), || {
                    black_box(compiled.agrees(black_box(items), 0));
                });
                let cached = super::FunctionScopes::new(items, compiled);
                cached.plan();
                super::measure_operation(&format!("{label} cached-plan"), || {
                    black_box(cached.plan());
                });
                if condition == "inner()" {
                    let crate::ast::Item::Match(documents) = &items[1] else {
                        unreachable!()
                    };
                    let crate::ast::Item::Function(inner) = &documents.items[0] else {
                        unreachable!()
                    };
                    let scopes = super::FunctionScopes::new(items, compiled);
                    let environment = scopes.get(inner).unwrap();
                    assert_eq!(environment.function("top").unwrap().name, "top");
                    super::measure_operation(&format!("{label} checked-get"), || {
                        let scopes = super::FunctionScopes::new(black_box(items), black_box(compiled));
                        black_box(scopes.get(black_box(inner)));
                    });
                    super::measure_operation(&format!("{label} live-outer-lookup"), || {
                        black_box(environment.function(black_box("top")));
                    });
                }
            }
        }
    }

    #[test]
    fn parsed_scopes_are_shared_but_mutated_items_are_replanned() {
        let mut ruleset = crate::parse::parse_ruleset("service cloud.firestore { function f() { return true; } match /{id} { function g() { return f(); } allow read: if g(); } }").unwrap();
        let original = ruleset.clone();
        let scopes = crate::scope::FunctionScopes::new(
            &ruleset.services[0].items,
            &ruleset.function_scopes[0],
        );
        assert!(std::sync::Arc::ptr_eq(
            scopes.plan(),
            &ruleset.function_scopes[0]
        ));
        let crate::ast::Item::Function(function) = &mut ruleset.services[0].items[0] else {
            unreachable!()
        };
        function.name = "renamed".into();
        function.body = crate::ast::Expr::new(
            crate::ast::ExprKind::Literal(crate::ast::Literal::Bool(false)),
            function.body.span,
            function.body.end,
        );
        let scopes = crate::scope::FunctionScopes::new(
            &ruleset.services[0].items,
            &ruleset.function_scopes[0],
        );
        assert!(std::sync::Arc::ptr_eq(
            scopes.plan(),
            &ruleset.function_scopes[0]
        ));
        let crate::ast::Item::Function(function) = &ruleset.services[0].items[0] else {
            unreachable!()
        };
        let environment = scopes.get(function).unwrap();
        assert!(std::ptr::eq(
            environment.function("renamed").unwrap(),
            function
        ));
        assert!(environment.function("f").is_none());
        ruleset.services[0].items.remove(0);
        let scopes = crate::scope::FunctionScopes::new(
            &ruleset.services[0].items,
            &ruleset.function_scopes[0],
        );
        assert!(!std::sync::Arc::ptr_eq(
            scopes.plan(),
            &ruleset.function_scopes[0]
        ));
        assert_eq!(original.services[0].items.len(), 2);
    }
    #[test]
    fn cached_plan_identity_does_not_change_ast_equality() {
        let original = crate::parse::parse_ruleset(
            "service cloud.firestore { function f() { return true; } }",
        )
        .unwrap();
        let mut changed = original.clone();
        changed.function_scopes.clear();
        assert_eq!(original, changed);
    }
}
