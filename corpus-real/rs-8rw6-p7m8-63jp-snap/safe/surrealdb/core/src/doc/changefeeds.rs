use anyhow::Result;

use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::Document;

impl Document {
	pub async fn process_changefeeds(&self, ctx: &FrozenContext, opt: &Options) -> Result<()> {

		if opt.import {
			return Ok(());
		}

		if !self.is_modified() {
			return Ok(());
		}

		let ns = self.doc_ctx.ns();

		let db = self.doc_ctx.db();

		let tb = self.doc_ctx.tb()?;

		let dbcf = db.changefeed.as_ref();

		let tbcf = tb.changefeed.as_ref();

		if let Some(cf) = dbcf.or(tbcf) {

			if let Some(id) = &self.id {
				ctx.tx().changefeed_buffer_record_change(
					ns.namespace_id,
					db.database_id,
					&tb.name,
					id.as_ref(),
					self.initial.doc.clone(),
					self.current.doc.clone(),
					cf.store_diff,
				);
			}
		}

		Ok(())
	}
}
