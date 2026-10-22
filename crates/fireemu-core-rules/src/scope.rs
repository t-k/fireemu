//! Source-owned lexical scope plans. Paths resolve against the live borrowed AST, so the plan
//! contains neither self references nor request bindings. Public AST mutations that change item
//! shape/offsets rebuild the plan; names, bodies and match captures are always read from the AST.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ast::{FunctionDecl, Item};

#[cfg(test)]
std::thread_local! { pub(crate) static PLAN_BUILDS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }

#[cfg(test)]
std::thread_local! { pub(crate) static LEGACY_EVALUATION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) }; }

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

    fn items<'a>(&self, root: &'a [Item], block: usize) -> &'a [Item] {
        let mut items = root;
        for &position in &self.blocks[block].path {
            let Item::Match(block) = &items[position] else {
                unreachable!("validated scope path")
            };
            items = &block.items;
        }
        items
    }
}

pub(crate) struct FunctionScopes<'a> {
    items: &'a [Item],
    pub(crate) plan: Arc<ServiceScopes>,
    #[cfg(test)]
    legacy: Option<BTreeMap<usize, Arc<crate::eval::LegacyFunctionEnvironment<'a>>>>,
}

impl<'a> FunctionScopes<'a> {
    pub(crate) fn new(items: &'a [Item], compiled: &Arc<ServiceScopes>) -> Self {
        Self {
            items,
            #[cfg(test)]
            legacy: LEGACY_EVALUATION.with(core::cell::Cell::get).then(|| {
                let mut scopes = BTreeMap::new();
                crate::eval::collect_function_scopes(items, None, &mut scopes);
                scopes
            }),
            plan: if compiled.agrees(items, 0) {
                Arc::clone(compiled)
            } else {
                ServiceScopes::compile(items)
            },
        }
    }

    pub(crate) fn get(&self, function: &FunctionDecl) -> Option<FunctionEnvironment<'a>> {
        #[cfg(test)]
        if let Some(legacy) = &self.legacy {
            return legacy
                .get(&(std::ptr::from_ref(function) as usize))
                .map(|environment| FunctionEnvironment {
                    items: self.items,
                    plan: Arc::clone(&self.plan),
                    scope: 0,
                    legacy: Some(Arc::clone(environment)),
                });
        }
        let &(scope, _) = self.plan.declarations.get(&function.span.offset)?.iter().find(|&&(scope, position)| {
            matches!(&self.plan.items(self.items, scope)[position], Item::Function(found) if std::ptr::eq(found, function))
        })?;
        Some(FunctionEnvironment {
            items: self.items,
            plan: Arc::clone(&self.plan),
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
                .items(self.items, id)
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
mod scope_plan_tests {
    #[test]
    fn parsed_scopes_are_shared_but_mutated_items_are_replanned() {
        let mut ruleset = crate::parse::parse_ruleset("service cloud.firestore { function f() { return true; } match /{id} { function g() { return f(); } allow read: if g(); } }").unwrap();
        let original = ruleset.clone();
        let scopes = crate::scope::FunctionScopes::new(
            &ruleset.services[0].items,
            &ruleset.function_scopes[0],
        );
        assert!(std::sync::Arc::ptr_eq(
            &scopes.plan,
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
            &scopes.plan,
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
            &scopes.plan,
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
