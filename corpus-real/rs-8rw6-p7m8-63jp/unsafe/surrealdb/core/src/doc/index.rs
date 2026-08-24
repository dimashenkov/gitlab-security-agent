
















use anyhow::Result;
use reblessive::tree::Stk;

use crate::catalog::{DatabaseDefinition, Index, IndexDefinition, TableDefinition};
use crate::ctx::FrozenContext;
use crate::dbs::{Force, Options};
use crate::doc::{CursorDoc, Document};
use crate::expr::FlowResultExt as _;
use crate::idx::index::IndexOperation;
use crate::kvs::index::{ConsumeResult, IndexMutation};
use crate::val::{RecordId, Value};

impl Document {
	pub(super) async fn store_index_data(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		let ixs = match &opt.force {
			Force::All => self.doc_ctx.ix()?,
			_ if self.is_modified() => self.doc_ctx.ix()?,
			_ => return Ok(()),
		};

		let db = self.doc_ctx.db();

		let tb = self.doc_ctx.tb()?;

		if tb.drop {
			return Ok(());
		}

		let rid = self.id()?;

		for ix in ixs.iter() {

			if ix.prepare_remove {
				continue;
			}

			let o = Self::build_opt_values(stk, ctx, opt, ix, &self.initial).await?;

			let n = Self::build_opt_values(stk, ctx, opt, ix, &self.current).await?;

			let count_cond_match = if let Index::Count(Some(cond)) = &ix.index {
				let old_matches = stk
					.run(|stk| cond.0.compute(stk, ctx, opt, Some(&self.initial)))
					.await
					.catch_return()?
					.is_truthy();
				let new_matches = stk
					.run(|stk| cond.0.compute(stk, ctx, opt, Some(&self.current)))
					.await
					.catch_return()?
					.is_truthy();
				Some((old_matches, new_matches))
			} else {
				None
			};




			let cond_changed = matches!(count_cond_match, Some((o, n)) if o != n);
			if o != n || cond_changed {
				Self::one_index(db, tb, stk, ctx, opt, ix, o, n, &rid, count_cond_match).await?;
			}
		}

		Ok(())
	}

	#[allow(clippy::too_many_arguments)]
	async fn one_index(
		db: &DatabaseDefinition,
		tb: &TableDefinition,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		ix: &IndexDefinition,
		o: Option<Vec<Value>>,
		n: Option<Vec<Value>>,
		rid: &RecordId,
		count_cond_match: Option<(bool, bool)>,
	) -> Result<()> {

		let (o, n) = if let Some(ib) = ctx.get_index_builder() {
			let mutation = IndexMutation {
				old_values: o,
				new_values: n,
				rid,
				count_cond_match,
			};
			match ib.consume(db, ctx, ix, mutation).await? {



				ConsumeResult::Enqueued => return Ok(()),

				ConsumeResult::Ignored(o, n) => (o, n),

				ConsumeResult::Retired => return Ok(()),
			}
		} else {
			(o, n)
		};

		let mut ic = IndexOperation::new(
			ctx,
			opt,
			db.namespace_id,
			db.database_id,
			tb.table_id,
			ix,
			o,
			n,
			rid,
		);

		if let Some((old_matches, new_matches)) = count_cond_match {
			ic = ic.with_count_cond_match(old_matches, new_matches);
		}

		let mut require_compaction = false;

		ic.compute(stk, &mut require_compaction).await?;

		if require_compaction {
			ic.trigger_compaction().await?;
		}
		Ok(())
	}





	pub(crate) async fn build_opt_values(
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		ix: &IndexDefinition,
		doc: &CursorDoc,
	) -> Result<Option<Vec<Value>>> {
		if doc.doc.as_ref().is_nullish() {
			return Ok(None);
		}
		let mut o = Vec::with_capacity(ix.cols.len());
		for i in ix.cols.iter() {
			let v = i.compute(stk, ctx, opt, Some(doc)).await.catch_return()?;
			o.push(v);
		}
		Ok(Some(o))
	}
}
