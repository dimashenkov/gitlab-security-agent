use reblessive::tree::Stk;

use super::IgnoreError;
use crate::ctx::FrozenContext;
use crate::dbs::{Options, Statement};
use crate::doc::Document;
use crate::val::Value;

impl Document {
	pub(crate) async fn delete(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		self.check_record_exists()?;




		self.check_delete_permissions(stk, ctx, opt, &self.current).await?;

		self.check_where_condition(stk, ctx, opt, stm.cond()).await?;

		self.cleanup_table_references(stk, ctx, opt).await?;

		self.clear_record_data();

		self.store_index_data(stk, ctx, opt).await?;
		self.purge_record_data(stk, ctx, opt).await?;
		self.process_table_views(stk, ctx, opt, super::Action::Delete).await?;
		self.process_table_events(stk, ctx, opt, super::Action::Delete).await?;
		self.process_table_lives(stk, ctx, opt, super::Action::Delete).await?;
		self.process_changefeeds(ctx, opt).await?;

		self.check_select_permissions(stk, ctx, opt, &self.initial).await?;

		self.output_write(stk, ctx, opt, stm.output(), stm).await
	}
}
