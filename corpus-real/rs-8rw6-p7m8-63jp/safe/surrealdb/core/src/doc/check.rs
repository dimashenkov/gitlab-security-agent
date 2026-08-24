use anyhow::{Result, bail, ensure};
use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use super::IgnoreError;
use crate::catalog::Permission;
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::compute::DocKind;
use crate::doc::{CursorDoc, Document, Extras};
use crate::err::Error;
use crate::expr::paths::{ID, IN, OUT};
use crate::expr::{Cond, FlowResultExt};
use crate::iam::Action;
use crate::val::{RecordId, Value};

impl Document {





	#[inline]
	pub(super) fn check_record_exists(&self) -> Result<(), IgnoreError> {

		if self.id.is_some() && self.current.doc.as_ref().is_none() {
			return Err(IgnoreError::Ignore);
		}

		Ok(())
	}





	#[inline]
	pub(super) fn check_table_type_create(&self) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		ensure!(
			tb.allows_normal(),
			Error::TableCheck {
				record: self.id()?.to_sql(),
				relation: false,
				target_type: tb.table_type.to_sql(),
			}
		);

		Ok(())
	}





	#[inline]
	pub(super) fn check_table_type_upsert(&self) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		ensure!(
			tb.allows_normal(),
			Error::TableCheck {
				record: self.id()?.to_sql(),
				relation: false,
				target_type: tb.table_type.to_sql(),
			}
		);

		Ok(())
	}





	#[inline]
	pub(super) fn check_table_type_relate(&self) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		ensure!(
			tb.allows_relation(),
			Error::TableCheck {
				record: self.id()?.to_sql(),
				relation: true,
				target_type: tb.table_type.to_sql(),
			}
		);

		Ok(())
	}





	#[inline]
	pub(super) fn check_table_type_insert(&self) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		match self.extras {
			Extras::Relate(_, _, _) => {
				ensure!(
					tb.allows_relation(),
					Error::TableCheck {
						record: self.id()?.to_sql(),
						relation: true,
						target_type: tb.table_type.to_sql(),
					}
				);
			}
			_ => {
				ensure!(
					tb.allows_normal(),
					Error::TableCheck {
						record: self.id()?.to_sql(),
						relation: false,
						target_type: tb.table_type.to_sql(),
					}
				);
			}
		};

		Ok(())
	}














	#[inline]
	pub(super) fn check_permissions_quick_create(
		&self,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<(), IgnoreError> {

		if self.id.is_some() {

			if ctx.check_perms(opt, Action::Edit)? {

				let table = self.doc_ctx.tb()?;

				if table.permissions.create.is_none() {
					return Err(IgnoreError::Ignore);
				}
			}
		}
		Ok(())
	}










	pub(super) fn check_data_fields(&self) -> Result<()> {

		fn check(found: Value, expected: &RecordId) -> Result<()> {
			match found {

				Value::RecordId(v) if v.key.is_range() => {
					bail!(Error::IdInvalid {
						value: v.to_sql(),
					})
				}

				Value::RecordId(v) if v.eq(expected) => Ok(()),






				Value::None => Ok(()),










				v if expected.key == v => Ok(()),

				v => {
					bail!(Error::IdMismatch {
						value: v.to_sql()
					})
				}
			}
		}




		if self.r#gen.is_some() {
			return Ok(());
		}

		let rid = self.id()?;

		ensure!(
			!rid.key.is_range(),
			Error::IdInvalid {
				value: rid.to_sql(),
			}
		);

		let data = self.input_data.as_ref();

		if data.is_some_and(|x| x.is_patch()) {
			return Ok(());
		}

		if let Extras::Normal = &self.extras {
			if let Some(data) = data {
				check(data.pick(ID.as_ref()), rid.as_ref())?;
			}
		}

		else if let Extras::Relate(l, r, v) = &self.extras {
			if let Some(data) = data {
				check(data.pick(ID.as_ref()), rid.as_ref())?;
				check(data.pick(IN.as_ref()), l)?;
				check(data.pick(OUT.as_ref()), r)?;
			} else if let Some(value) = v {
				check(value.pick(ID.as_ref()), rid.as_ref())?;
				check(value.pick(IN.as_ref()), l)?;
				check(value.pick(OUT.as_ref()), r)?;
			}
		}

		Ok(())
	}







	pub(super) async fn check_where_condition(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		cond: Option<&Cond>,
	) -> Result<(), IgnoreError> {

		if self.is_key_only_iteration() {
			return Ok(());
		}

		let Some(cond) = cond else {
			return Ok(());
		};

		if self.reduction_required(ctx, opt)? {





			let _ = self.reduce_current(stk, ctx, opt).await?;


			self.compute_fields(stk, ctx, opt, DocKind::CurrentReduced, None).await?;

			let doc: &CursorDoc = self.current_reduced.as_ref().unwrap_or(&self.current);

			if !stk
				.run(|stk| cond.0.compute(stk, ctx, opt, Some(doc)))
				.await
				.catch_return()?
				.is_truthy()
			{
				return Err(IgnoreError::Ignore);
			}
		} else {

			self.compute_fields(stk, ctx, opt, DocKind::Current, None).await?;

			if !stk
				.run(|stk| cond.0.compute(stk, ctx, opt, Some(&self.current)))
				.await
				.catch_return()?
				.is_truthy()
			{
				return Err(IgnoreError::Ignore);
			}
		}

		Ok(())
	}




	pub(super) async fn check_select_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		if self.id.is_some() && ctx.check_perms(opt, Action::View)? {
			self.process_permissions(stk, ctx, opt, doc, &self.doc_ctx.tb()?.permissions.select)
				.await?;
		}
		Ok(())
	}




	pub(super) async fn check_create_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		if self.id.is_some() && ctx.check_perms(opt, Action::Edit)? {
			self.process_permissions(stk, ctx, opt, doc, &self.doc_ctx.tb()?.permissions.create)
				.await?;
		}
		Ok(())
	}




	pub(super) async fn check_update_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		if self.id.is_some() && ctx.check_perms(opt, Action::Edit)? {
			self.process_permissions(stk, ctx, opt, doc, &self.doc_ctx.tb()?.permissions.update)
				.await?;
		}
		Ok(())
	}




	pub(super) async fn check_delete_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		if self.id.is_some() && ctx.check_perms(opt, Action::Edit)? {
			self.process_permissions(stk, ctx, opt, doc, &self.doc_ctx.tb()?.permissions.delete)
				.await?;
		}
		Ok(())
	}






	pub(super) async fn recheck_update_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		if matches!(&self.doc_ctx.tb()?.permissions.update, Permission::Specific(_)) {
			self.check_update_permissions(stk, ctx, opt, doc).await?;
		}
		Ok(())
	}











	async fn process_permissions(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: &CursorDoc,
		perms: &Permission,
	) -> Result<(), IgnoreError> {
		match perms {
			Permission::None => Err(IgnoreError::Ignore),
			Permission::Full => Ok(()),
			Permission::Specific(e) => {

				let opt = &opt.new_with_perms(false);

				if !stk
					.run(|stk| e.compute(stk, ctx, opt, Some(doc)))
					.await
					.catch_return()?
					.is_truthy()
				{
					return Err(IgnoreError::Ignore);
				}
				Ok(())
			}
		}
	}
}
