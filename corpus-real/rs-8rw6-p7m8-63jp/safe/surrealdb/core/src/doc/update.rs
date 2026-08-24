use reblessive::tree::Stk;

use super::IgnoreError;
use crate::ctx::FrozenContext;
use crate::dbs::{Options, Statement};
use crate::doc::Document;
use crate::val::Value;

impl Document {
	pub(crate) async fn update(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		self.check_record_exists()?;




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
