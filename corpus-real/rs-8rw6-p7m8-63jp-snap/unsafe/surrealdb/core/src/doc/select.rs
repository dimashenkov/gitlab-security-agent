use reblessive::tree::Stk;

use super::IgnoreError;
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::Document;
use crate::expr::{Idiom, SelectStatement};
use crate::val::Value;

impl Document {
	pub(crate) async fn select(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &SelectStatement,
		omit: &[Idiom],
	) -> Result<Value, IgnoreError> {

		self.check_record_exists()?;


		self.check_select_permissions(stk, ctx, opt, &self.current).await?;

		self.check_where_condition(stk, ctx, opt, stm.cond.as_ref()).await?;

		self.output_select(stk, ctx, opt, stm, omit).await
	}
}
