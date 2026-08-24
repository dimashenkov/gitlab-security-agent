use reblessive::tree::Stk;

use super::IgnoreError;
use crate::ctx::FrozenContext;
use crate::dbs::{Options, Statement};
use crate::doc::Document;
use crate::val::Value;

impl Document {
	pub(crate) async fn create(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Value, IgnoreError> {

		self.check_permissions_quick_create(ctx, opt)?;

		self.compute_input_data(stk, ctx, opt, stm).await?;

		self.process_record_data(stk, ctx, opt).await?;

		self.generate_record_id()?;

		self.check_table_type_create()?;

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
}
