//! Diagnostic expression structure and result histograms. These never decide access.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::Json;

#[derive(Debug, Clone)]
pub(crate) struct Template {
    pub at: usize,
    pub end: usize,
    pub children: Vec<usize>,
}

type Histograms = Vec<Vec<(Json, i64)>>;

#[derive(Debug)]
struct Collection {
    templates: Vec<Template>,
    text: Vec<char>,
    positions: Vec<(usize, usize)>,
    values: Mutex<Histograms>,
    enabled: AtomicBool,
}

#[derive(Debug, Clone)]
pub(crate) struct Coverage(Arc<Collection>);

impl Coverage {
    pub fn new(text: &str, anchor: (usize, usize), templates: Vec<Template>) -> Self {
        let mut position = (anchor.0.saturating_sub(1), anchor.1.saturating_sub(1));
        let mut positions = Vec::new();
        let text: Vec<char> = text.chars().collect();
        for character in &text {
            positions.push(position);
            if *character == '\n' {
                position = (position.0 + 1, 0);
            } else {
                position.1 += character.len_utf16();
            }
        }
        positions.push(position);
        let values = Mutex::new(vec![Vec::new(); templates.len()]);
        Self(Arc::new(Collection {
            templates,
            text,
            positions,
            values,
            enabled: AtomicBool::new(true),
        }))
    }

    pub fn enabled(&self, enabled: bool) {
        self.0.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn observer(&self) -> Observer<'_> {
        Observer {
            collection: &self.0,
            values: self
                .0
                .values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            enabled: self.0.enabled.load(Ordering::Relaxed),
            suppressed: 0,
            variables: BTreeMap::new(),
        }
    }

    pub fn report(&self, root: usize) -> Json {
        let values = self
            .0
            .values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Parser IDs are topological, so even flat authorization chains need no recursive walk.
        let mut built: Vec<Option<Json>> = vec![None; self.0.templates.len()];
        for (id, template) in self.0.templates.iter().enumerate() {
            let (row, column) = self.0.positions[template.at];
            let (end_row, end_column) = self.0.positions[template.end - 1];
            let width = self.0.text[template.end - 1].len_utf16();
            let mut fields = BTreeMap::from([
                (
                    "location-start".to_owned(),
                    Json::string(format!("{row}:{column}")),
                ),
                (
                    "location-end".to_owned(),
                    Json::string(format!("{end_row}:{}", end_column + width - 1)),
                ),
                (
                    "text".to_owned(),
                    Json::String(self.0.text[template.at..template.end].iter().collect()),
                ),
                (
                    "values".to_owned(),
                    Json::Array(
                        values[id]
                            .iter()
                            .map(|(value, count)| {
                                Json::object([
                                    ("value", value.clone()),
                                    ("count", Json::int(*count)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]);
            if !template.children.is_empty() {
                fields.insert(
                    "children".to_owned(),
                    Json::Array(
                        template
                            .children
                            .iter()
                            .map(|child| {
                                built[*child]
                                    .take()
                                    .expect("a diagnostic node has one parent")
                            })
                            .collect(),
                    ),
                );
            }
            built[id] = Some(Json::Object(fields));
        }
        built[root]
            .take()
            .expect("the expression has a diagnostic root")
    }
}

pub(crate) struct Observer<'a> {
    collection: &'a Collection,
    values: MutexGuard<'a, Histograms>,
    enabled: bool,
    pub suppressed: usize,
    variables: BTreeMap<String, Json>,
}

impl Observer<'_> {
    pub fn record(&mut self, id: usize, value: Json) {
        if !self.enabled || self.suppressed != 0 {
            return;
        }
        let histogram = &mut self.values[id];
        if let Some((_, count)) = histogram.iter_mut().find(|(seen, _)| seen == &value) {
            *count = count.saturating_add(1);
        } else {
            histogram.push((value, 1));
        }
    }

    pub fn member_name(&mut self, id: usize, name: &str) {
        if let Some(name_id) = self.collection.templates[id].children.get(1).copied() {
            self.record(name_id, Json::string(name));
        }
    }

    pub fn opaque(&mut self, variable: Option<&str>) -> Json {
        // Process-local identities represent evaluations, never Firebase object identities.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let fresh = || Json::string(format!("hash@{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        variable.map_or_else(fresh, |name| {
            self.variables
                .entry(name.to_owned())
                .or_insert_with(fresh)
                .clone()
        })
    }

    pub fn prefixes(&self, root: usize, operands: usize) -> Vec<usize> {
        let mut ids = vec![root];
        for _ in 2..operands {
            ids.push(self.collection.templates[*ids.last().expect("root exists")].children[0]);
        }
        ids.reverse();
        ids
    }
}
