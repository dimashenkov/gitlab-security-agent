use anyhow::anyhow;
use reblessive::tree::Stk;

use super::IgnoreError;
use crate::catalog::providers::TableProvider;
use crate::ctx::FrozenContext;
use crate::dbs::{Options, Statement};
use crate::doc::Document;
use crate::err::Error;
use crate::val::Value;

impl Document {
	pub(crate) async fn upsert(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		let mut error: Option<anyhow::Error> = None;

		if !self.is_iteration_initial() {
			return self.upsert_update(stk, ctx, opt, stm).await;
		}

		ctx.tx().new_save_point().await?;

		let retry = match self.upsert_create(stk, ctx, opt, stm).await {

			Ok(x) => {
				ctx.tx().release_last_save_point().await?;
				return Ok(x);
			}

			Err(IgnoreError::Ignore) => {
				ctx.tx().release_last_save_point().await?;
				return Err(IgnoreError::Ignore);
			}

			Err(IgnoreError::Error(e)) => match e.downcast() {

				Ok(Error::IndexExists {
					record,
					..
				}) if !self.is_specific_record_id() => record,

				Ok(Error::RecordExists {
					record,
				}) => record,

				Ok(e) if e.is_schema_related() && stm.is_repeatable() => {
					error = Some(e.into());
					self.inner_id()?
				}

				Ok(e) => {
					ctx.tx().rollback_to_save_point().await?;
					self.mutated = false;
					return Err(IgnoreError::Error(anyhow!(e)));
				}

				Err(e) => {
					ctx.tx().rollback_to_save_point().await?;
					self.mutated = false;
					return Err(IgnoreError::Error(e));
				}
			},
		};

		ctx.tx().rollback_to_save_point().await?;

		self.mutated = false;

		if ctx.is_done(None).await? {
			return Err(IgnoreError::Ignore);
		}

		let ns = self.doc_ctx.ns().namespace_id;

		let db = self.doc_ctx.db().database_id;

		let val = ctx.tx().get_record(ns, db, &retry.table, &retry.key, opt.version).await?;

		self.modify_for_update_retry(retry, val);

		let res = self.upsert_update(stk, ctx, opt, stm).await;

		match error {
			Some(e) => match res {
				Err(_) => Err(IgnoreError::Error(e)),
				Ok(v) => Ok(v),
			},
			None => res,
		}
	}



	async fn upsert_create(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		self.check_table_type_upsert()?;

		self.check_permissions_quick_create(ctx, opt)?;

		self.compute_input_data(stk, ctx, opt, stm).await?;

		self.process_record_data(stk, ctx, opt).await?;

		self.generate_record_id()?;

		self.check_data_fields()?;

		self.default_record_data()?;

		self.process_table_fields(stk, ctx, opt, stm).await?;

		self.cleanup_table_fields()?;

		self.check_create_permissions(stk, ctx, opt, &self.current).await?;

		self.store_record_data(ctx, stm).await?;
		self.store_index_data(stk, ctx, opt).await?;

		self.process_table_references(stk, ctx, opt).await?;
		self.process_table_views(stk, ctx, opt, super::Action::Create).await?;
		self.process_table_events(stk, ctx, opt, super::Action::Create).await?;
		self.process_table_lives(stk, ctx, opt, super::Action::Create).await?;
		self.process_changefeeds(ctx, opt).await?;

		self.check_select_permissions(stk, ctx, opt, &self.current).await?;

		self.output_write(stk, ctx, opt, stm.output(), stm).await
	}



	async fn upsert_update(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		self.check_record_exists()?;

		self.check_table_type_upsert()?;




		self.check_update_permissions(stk, ctx, opt, &self.current).await?;

		self.compute_input_data(stk, ctx, opt, stm).await?;

		self.check_data_fields()?;

		self.check_where_condition(stk, ctx, opt, stm.cond()).await?;

		self.process_record_data(stk, ctx, opt).await?;

		self.default_record_data()?;

		self.process_table_fields(stk, ctx, opt, stm).await?;

		self.cleanup_table_fields()?;

		self.recheck_update_permissions(stk, ctx, opt, &self.current).await?;

		self.store_record_data(ctx, stm).await?;
		self.store_index_data(stk, ctx, opt).await?;

		self.process_table_references(stk, ctx, opt).await?;
		self.process_table_views(stk, ctx, opt, super::Action::Update).await?;
		self.process_table_events(stk, ctx, opt, super::Action::Update).await?;
		self.process_table_lives(stk, ctx, opt, super::Action::Update).await?;
		self.process_changefeeds(ctx, opt).await?;

		self.check_select_permissions(stk, ctx, opt, &self.current).await?;

		self.output_write(stk, ctx, opt, stm.output(), stm).await
	}
}
