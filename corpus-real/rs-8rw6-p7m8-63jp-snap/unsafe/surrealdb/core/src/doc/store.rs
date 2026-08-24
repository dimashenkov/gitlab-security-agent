use anyhow::Result;

use crate::catalog::providers::TableProvider;
use crate::ctx::FrozenContext;
use crate::dbs::Statement;
use crate::doc::Document;
use crate::err::Error;

impl Document {
	pub(super) async fn store_record_data(
		&mut self,
		ctx: &FrozenContext,
		stm: &Statement<'_>,
	) -> Result<()> {

		if !self.is_modified() {
			return Ok(());
		}

		let tb = self.doc_ctx.tb()?;

		if tb.drop {
			return Ok(());
		}

		let rid = self.id()?;

		let ns = self.doc_ctx.ns().namespace_id;

		let db = self.doc_ctx.db().database_id;

		let doc = self.current.doc.clone().into_read_only();

		match stm {









			Statement::Insert(_) if self.is_iteration_initial() => {
				match ctx.tx().put_record(ns, db, &rid.table, &rid.key, doc).await {

					Err(e) => {
						if matches!(
							e.downcast_ref(),
							Some(Error::Kvs(crate::kvs::Error::TransactionKeyAlreadyExists))
						) {
							Err(anyhow::Error::new(Error::RecordExists {
								record: rid.as_ref().to_owned(),
							}))
						} else {
							Err(e)
						}
					}

					x => x,
				}
			}






			Statement::Upsert(_) if self.is_iteration_initial() => {
				match ctx.tx().put_record(ns, db, &rid.table, &rid.key, doc).await {

					Err(e) => {
						if matches!(
							e.downcast_ref(),
							Some(Error::Kvs(crate::kvs::Error::TransactionKeyAlreadyExists))
						) {
							Err(anyhow::Error::new(Error::RecordExists {
								record: rid.as_ref().to_owned(),
							}))
						} else {
							Err(e)
						}
					}

					x => x,
				}
			}






			Statement::Create(_) => {
				match ctx.tx().put_record(ns, db, &rid.table, &rid.key, doc).await {

					Err(e) => {
						if matches!(
							e.downcast_ref(),
							Some(Error::Kvs(crate::kvs::Error::TransactionKeyAlreadyExists))
						) {
							Err(anyhow::Error::new(Error::RecordExists {
								record: rid.as_ref().to_owned(),
							}))
						} else {
							Err(e)
						}
					}
					x => x,
				}
			}








			Statement::Relate(_) if self.initial.doc.as_ref().is_nullish() => {
				match ctx.tx().put_record(ns, db, &rid.table, &rid.key, doc).await {
					Err(e) => {
						if matches!(
							e.downcast_ref(),
							Some(Error::Kvs(crate::kvs::Error::TransactionKeyAlreadyExists))
						) {
							Err(anyhow::Error::new(Error::RecordExists {
								record: rid.as_ref().to_owned(),
							}))
						} else {
							Err(e)
						}
					}
					x => x,
				}
			}

			_ => ctx.tx().set_record(ns, db, &rid.table, &rid.key, doc).await,
		}?;



		self.mutated = true;
		Ok(())
	}
}
