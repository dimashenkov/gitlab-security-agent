use std::sync::Arc;

use anyhow::Result;
use reblessive::tree::Stk;
use tracing::instrument;

use crate::catalog::Permission;
use crate::ctx::{Context, FrozenContext};
use crate::dbs::Options;
use crate::doc::{CursorDoc, Document};
use crate::expr::FlowResultExt as _;
use crate::iam::{Action, AuthLimit};

impl Document {






	#[inline]
	pub(crate) fn reduction_required(&self, ctx: &FrozenContext, opt: &Options) -> Result<bool> {

		if self.id.is_none() {
			return Ok(false);
		}

		if !ctx.check_perms(opt, Action::View)? {
			return Ok(false);
		}

		Ok(true)
	}












	pub(crate) async fn reduce_current(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<&mut CursorDoc> {

		if self.reduction_required(ctx, opt)? {

			if self.current_reduced.is_none() {
				self.current_reduced =
					Some(self.reduce_document(stk, ctx, opt, &self.current).await?);
			}

			self.current_reduced
				.as_mut()
				.ok_or_else(|| anyhow::anyhow!("current_reduced should be set"))
		} else {
			Ok(&mut self.current)
		}
	}












	pub(crate) async fn reduce_initial(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<&mut CursorDoc> {

		if self.reduction_required(ctx, opt)? {

			if self.initial_reduced.is_none() {
				self.initial_reduced =
					Some(self.reduce_document(stk, ctx, opt, &self.initial).await?);
			}

			self.initial_reduced
				.as_mut()
				.ok_or_else(|| anyhow::anyhow!("initial_reduced should be set"))
		} else {
			Ok(&mut self.initial)
		}
	}
















	pub(crate) async fn reduce_to_owned(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		full: &CursorDoc,
	) -> Result<CursorDoc> {
		if self.reduction_required(ctx, opt)? {
			self.reduce_document(stk, ctx, opt, full).await
		} else {
			Ok(full.clone())
		}
	}










	#[instrument(level = "trace", target = "surrealdb::core::doc::reduce", skip_all)]
	pub(crate) async fn filter_computed_field_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &mut CursorDoc,
	) -> Result<()> {

		if !ctx.check_perms(opt, Action::View)? {
			return Ok(());
		}



		if !self.has_computed_fields() {
			return Ok(());
		}



		let original = doc.clone();
		for fd in self.doc_ctx.fd()?.iter() {


			if fd.computed.is_none() {
				continue;
			}



			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);
			match &fd.select_permission {
				Permission::Full => (),
				Permission::None => {
					for k in original.doc.as_ref().each(&fd.name).iter() {
						doc.doc.to_mut().cut(k);
					}
				}
				Permission::Specific(e) => {
					for k in original.doc.as_ref().each(&fd.name).iter() {

						let opt = &opt.new_with_perms(false);

						let val = Arc::new(original.doc.as_ref().pick(k));

						let mut child_ctx = Context::new_child(ctx);
						child_ctx.add_value("value", val);
						let child_ctx = child_ctx.freeze();

						if !stk
							.run(|stk| e.compute(stk, &child_ctx, opt, Some(&original)))
							.await
							.catch_return()?
							.is_truthy()
						{
							doc.doc.to_mut().cut(k);
						}
					}
				}
			}
		}
		Ok(())
	}






	async fn reduce_document(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		full: &CursorDoc,
	) -> Result<CursorDoc> {

		let mut reduced = full.doc.clone();

		for fd in self.doc_ctx.fd()?.iter() {




			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);

			for k in reduced.as_ref().each(&fd.name).iter() {

				match &fd.select_permission {
					Permission::Full => (),
					Permission::None => reduced.to_mut().cut(k),
					Permission::Specific(e) => {

						let opt = &opt.new_with_perms(false);

						let val = Arc::new(full.doc.as_ref().pick(k));

						let mut ctx = Context::new_child(ctx);
						ctx.add_value("value", val);
						let ctx = ctx.freeze();

						if !stk
							.run(|stk| e.compute(stk, &ctx, opt, Some(full)))
							.await
							.catch_return()?
							.is_truthy()
						{
							reduced.to_mut().cut(k);
						}
					}
				}
			}
		}

		Ok(CursorDoc::new(full.rid.clone(), full.ir.clone(), reduced))
	}
}
