use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use crate::catalog::FieldDefinition;
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::{CursorDoc, Document};
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::val::RecordId;








#[derive(Clone, Copy, Debug)]
pub(super) enum DocKind {
	Initial,
	Current,
	InitialReduced,
	CurrentReduced,
}

impl Document {



	pub(super) fn has_computed_fields(&self) -> bool {
		match self.doc_ctx.fd() {
			Ok(fields) => fields.iter().any(|fd| fd.computed.is_some()),
			Err(_) => false,
		}
	}
















	pub(super) async fn compute_fields(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc_kind: DocKind,
		needed_roots: Option<&HashSet<String>>,
	) -> anyhow::Result<()> {

		if !self.has_computed_fields() {
			return Ok(());
		}


		let Ok(rid) = self.id() else {
			return Ok(());
		};
		let fields = Arc::clone(self.doc_ctx.fd()?);



		let doc: &mut CursorDoc = match doc_kind {
			DocKind::Initial => &mut self.initial,
			DocKind::Current => &mut self.current,
			DocKind::InitialReduced => match self.initial_reduced.as_mut() {
				Some(d) => d,
				None => return Ok(()),
			},
			DocKind::CurrentReduced => match self.current_reduced.as_mut() {
				Some(d) => d,
				None => return Ok(()),
			},
		};

		let Some(needed_roots) = needed_roots else {
			return Document::computed_fields_inner(
				stk,
				ctx,
				opt,
				rid.as_ref(),
				&fields,
				doc,
				None,
			)
			.await;
		};


		let mut dep_map: HashMap<String, crate::expr::computed_deps::ComputedDeps> = HashMap::new();
		for fd in fields.iter() {
			if fd.computed.is_none() {
				continue;
			}
			let field_name = fd.name.to_raw_string();
			let deps = if let Some(cd) = &fd.computed_deps {
				crate::expr::computed_deps::ComputedDeps {
					fields: cd.fields.clone(),
					is_complete: cd.is_complete,
				}
			} else if let Some(expr) = &fd.computed {
				crate::expr::computed_deps::extract_computed_deps(expr)
			} else {
				crate::expr::computed_deps::ComputedDeps::default()
			};
			dep_map.insert(field_name, deps);
		}



		let required = match crate::expr::computed_deps::resolve_required_computed_fields(
			needed_roots,
			&dep_map,
		) {
			Some(required) => required,
			None => {
				return Document::computed_fields_inner(
					stk,
					ctx,
					opt,
					rid.as_ref(),
					&fields,
					doc,
					None,
				)
				.await;
			}
		};




		let has_required_computed = required.iter().any(|name| dep_map.contains_key(name));
		if !has_required_computed {
			return Ok(());
		}

		Document::computed_fields_inner(stk, ctx, opt, rid.as_ref(), &fields, doc, Some(&required))
			.await
	}

	pub(super) async fn computed_fields_inner(
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		rid: &RecordId,
		fields: &[FieldDefinition],
		doc: &mut CursorDoc,
		required: Option<&HashSet<String>>,
	) -> anyhow::Result<()> {



		if required.is_none() && doc.fields_computed {
			return Ok(());
		}


		for fd in fields.iter() {
			let Some(computed) = &fd.computed else {
				continue;
			};

			if let Some(required) = required {
				let field_name = fd.name.to_raw_string();
				if !required.contains(&field_name) {
					continue;
				}
			}

			let mut val = computed.compute(stk, ctx, opt, Some(doc)).await.catch_return()?;
			if let Some(kind) = fd.field_kind.as_ref() {
				val = val.coerce_to_kind(kind).map_err(|e| Error::FieldCoerce {
					record: rid.to_sql(),
					field_name: fd.name.to_sql(),
					error: Box::new(e),
				})?;
			}

			doc.doc.to_mut().put(&fd.name, val);
		}




		if required.is_none() {
			doc.fields_computed = true;
		}

		Ok(())
	}
}
