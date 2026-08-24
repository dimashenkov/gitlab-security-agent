











use std::sync::Arc;

use anyhow::Result;
use reblessive::tree::Stk;

use super::IgnoreError;
use crate::catalog::Permission;
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{Options, Statement};
use crate::doc::compute::DocKind;
use crate::doc::{CursorDoc, Document};
use crate::expr::field::Fields;
use crate::expr::part::Part;
use crate::expr::{FlowResultExt, Idiom, Operation, Output, SelectStatement};
use crate::iam::{Action, AuthLimit};
use crate::val::Value;

impl Document {








	pub(super) async fn output_select(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stmt: &SelectStatement,
		omit: &[Idiom],
	) -> Result<Value, IgnoreError> {

		if self.is_key_only_iteration() {
			return Ok(self.current.doc.as_ref().clone());
		}

		let mut needed_roots = {
			let omit_exprs: Vec<crate::expr::Expr> =
				omit.iter().cloned().map(crate::expr::Expr::Idiom).collect();
			crate::exec::planner::Planner::extract_needed_fields(
				&stmt.fields,
				&omit_exprs,
				stmt.cond.as_ref(),
				stmt.order.as_ref(),
				stmt.group.as_ref(),
				stmt.split.as_ref(),
			)
		};

		if let Some(ref mut roots) = needed_roots
			&& self.id.is_some()
			&& ctx.check_perms(opt, Action::View)?
		{
			let table_fields = self.doc_ctx.fd()?;
			let mut opaque = false;
			for fd in table_fields.iter() {
				if let Permission::Specific(ref e) = fd.select_permission {
					let deps = crate::expr::computed_deps::extract_computed_deps(e);
					if !deps.is_complete {
						opaque = true;
						break;
					}
					roots.extend(deps.fields);
				}
			}
			if opaque {
				needed_roots = None;
			}
		}

		self.compute_fields(stk, ctx, opt, DocKind::Current, needed_roots.as_ref()).await?;

		let _ = self.reduce_current(stk, ctx, opt).await?;

		if self.current_reduced.is_some() {

			self.compute_fields(stk, ctx, opt, DocKind::CurrentReduced, needed_roots.as_ref())
				.await?;
		}

		let current: &CursorDoc = self.current_reduced.as_ref().unwrap_or(&self.current);

		let mut out = if stmt.group.is_some()
			|| (stmt.order.is_some() && matches!(stmt.fields, Fields::Value(_)))
		{





			let mut doc = current.doc.as_ref().clone();

			if stmt.order.is_some()
				&& let Fields::Value(ref sel) = stmt.fields
				&& let Some(ref alias) = sel.alias
				&& alias.len() == 1
				&& let Some(Part::Field(name)) = alias.first()
			{
				let val = stk
					.run(|stk| sel.expr.compute(stk, ctx, opt, Some(current)))
					.await
					.catch_return()?;
				if let Value::Object(ref mut obj) = doc {
					obj.insert(name.clone(), val);
				}
			}
			doc
		} else if !omit.is_empty() && matches!(stmt.fields, Fields::Value(_)) {



			let mut doc = current.doc.as_ref().clone();
			for field in omit {
				doc.del(stk, ctx, opt, field).await?;
			}
			let projection_doc = CursorDoc::new(current.rid.clone(), None, doc);
			stmt.fields.compute(stk, ctx, opt, Some(&projection_doc)).await?
		} else {
			stmt.fields.compute(stk, ctx, opt, Some(current)).await?
		};

		self.apply_select_field_permissions(stk, ctx, opt, &mut out).await?;




		if stmt.group.is_none() && !matches!(stmt.fields, Fields::Value(_)) {
			for field in omit {
				out.del(stk, ctx, opt, field).await?;
			}
		}

		Ok(out)
	}





	pub(super) async fn output_write(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		output: Option<&Output>,
		statement: &Statement<'_>,
	) -> Result<Value, IgnoreError> {




		if opt.import {
			return Err(IgnoreError::Ignore);
		}

		self.current_reduced = None;

		let mut out = match output {
			Some(Output::None) => return Err(IgnoreError::Ignore),
			Some(Output::Null) => Value::Null,
			Some(Output::Diff) => self.output_diff(stk, ctx, opt).await?,
			Some(Output::After) => self.output_after(stk, ctx, opt).await?,
			Some(Output::Before) => self.output_before(stk, ctx, opt).await?,
			Some(Output::Fields(v)) => self.output_fields(stk, ctx, opt, v).await?,
			None => match statement {
				Statement::Create(_)
				| Statement::Upsert(_)
				| Statement::Update(_)
				| Statement::Relate(_)
				| Statement::Insert(_) => self.output_after(stk, ctx, opt).await?,
				_ => return Err(IgnoreError::Ignore),
			},
		};

		self.apply_select_field_permissions(stk, ctx, opt, &mut out).await?;

		Ok(out)
	}



	async fn output_after(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<Value> {

		let _ = self.reduce_current(stk, ctx, opt).await?;

		let kind = if self.current_reduced.is_some() {
			DocKind::CurrentReduced
		} else {
			DocKind::Current
		};
		self.compute_fields(stk, ctx, opt, kind, None).await?;

		let current: &CursorDoc = self.current_reduced.as_ref().unwrap_or(&self.current);

		Ok(current.doc.as_ref().to_owned())
	}


	async fn output_before(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<Value> {

		let _ = self.reduce_initial(stk, ctx, opt).await?;

		let kind = if self.initial_reduced.is_some() {
			DocKind::InitialReduced
		} else {
			DocKind::Initial
		};
		self.compute_fields(stk, ctx, opt, kind, None).await?;

		let initial: &CursorDoc = self.initial_reduced.as_ref().unwrap_or(&self.initial);

		Ok(initial.doc.as_ref().to_owned())
	}


	async fn output_diff(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<Value> {

		let _ = self.reduce_initial(stk, ctx, opt).await?;
		let _ = self.reduce_current(stk, ctx, opt).await?;

		let reduced = self.initial_reduced.is_some();
		let (ki, kc) = if reduced {
			(DocKind::InitialReduced, DocKind::CurrentReduced)
		} else {
			(DocKind::Initial, DocKind::Current)
		};
		self.compute_fields(stk, ctx, opt, ki, None).await?;
		self.compute_fields(stk, ctx, opt, kc, None).await?;

		let initial: &CursorDoc = self.initial_reduced.as_ref().unwrap_or(&self.initial);
		let current: &CursorDoc = self.current_reduced.as_ref().unwrap_or(&self.current);

		let ops = initial.doc.as_ref().diff(current.doc.as_ref());
		Ok(Operation::operations_to_value(ops))
	}



	async fn output_fields(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		fields: &Fields,
	) -> Result<Value> {

		let _ = self.reduce_initial(stk, ctx, opt).await?;
		let _ = self.reduce_current(stk, ctx, opt).await?;

		let reduced = self.initial_reduced.is_some();
		let (ki, kc) = if reduced {
			(DocKind::InitialReduced, DocKind::CurrentReduced)
		} else {
			(DocKind::Initial, DocKind::Current)
		};
		self.compute_fields(stk, ctx, opt, ki, None).await?;
		self.compute_fields(stk, ctx, opt, kc, None).await?;

		let initial: &CursorDoc = self.initial_reduced.as_ref().unwrap_or(&self.initial);
		let current: &CursorDoc = self.current_reduced.as_ref().unwrap_or(&self.current);

		let mut child_ctx = Context::new_child(ctx);
		child_ctx.add_value("after", current.doc.as_arc());
		child_ctx.add_value("before", initial.doc.as_arc());
		let child_ctx = child_ctx.freeze();

		fields.compute(stk, &child_ctx, opt, Some(current)).await
	}












	async fn apply_select_field_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		out: &mut Value,
	) -> Result<()> {

		if self.id.is_none() {
			return Ok(());
		}

		if !ctx.check_perms(opt, Action::View)? {
			return Ok(());
		}

		for fd in self.doc_ctx.fd()?.iter() {




			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);

			for k in out.each(&fd.name).iter() {

				match &fd.select_permission {
					Permission::Full => (),
					Permission::None => out.cut(k),
					Permission::Specific(e) => {

						let opt = &opt.new_with_perms(false);

						let val = Arc::new(self.current.doc.as_ref().pick(k));

						let mut child_ctx = Context::new_child(ctx);
						child_ctx.add_value("value", val);
						let child_ctx = child_ctx.freeze();

						if !stk
							.run(|stk| e.compute(stk, &child_ctx, opt, Some(&self.current)))
							.await
							.catch_return()?
							.is_truthy()
						{
							out.cut(k);
						}
					}
				}
			}
		}
		Ok(())
	}
}
