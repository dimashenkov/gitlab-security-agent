use anyhow::{Result, ensure};
use surrealdb_types::ToSql;

use crate::catalog::providers::TableProvider;
use crate::catalog::{LATEST_EDGE_VARIANT, Relation, TableType};
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::{Document, Extras};
use crate::err::Error;
use crate::expr::Dir;
use crate::expr::paths::{IN, OUT};
use crate::key::graph;

impl Document {












	pub(super) async fn store_edges_data(
		&mut self,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		if tb.drop {
			return Ok(());
		}

		if let Extras::Relate(l, r, _) = &self.extras {

			let ns = self.doc_ctx.ns().namespace_id;

			let db = self.doc_ctx.db().database_id;

			let rid = self.id()?;

			let txn = ctx.tx();

			if matches!(
				tb.table_type,
				TableType::Relation(Relation {
					enforced: true,
					..
				})
			) {

				ensure!(
					txn.record_exists(ns, db, &l.table, &l.key, opt.version).await?,
					Error::IdNotFound {
						rid: l.to_sql(),
					}
				);

				ensure!(
					txn.record_exists(ns, db, &r.table, &r.key, opt.version).await?,
					Error::IdNotFound {
						rid: r.to_sql(),
					}
				);
			}






















			let etl = graph::new(ns, db, &rid.table, &rid.key, Dir::In, l);
			let etr = graph::new(ns, db, &rid.table, &rid.key, Dir::Out, r);





			let variant = self.initial.doc.edge_variant().unwrap_or(LATEST_EDGE_VARIANT);

			match variant {
				1 => {

					let ltr_legacy = graph::new(ns, db, &l.table, &l.key, Dir::Out, &rid);
					let rtl_legacy = graph::new(ns, db, &r.table, &r.key, Dir::In, &rid);
					futures::try_join!(txn.del(&ltr_legacy), txn.del(&rtl_legacy))?;

					let ltr = graph::new_pointer(ns, db, &l.table, &l.key, Dir::Out, &rid, r);
					let rtl = graph::new_pointer(ns, db, &r.table, &r.key, Dir::In, &rid, l);
					futures::try_join!(
						txn.set(&ltr, &()),
						txn.set(&etl, &()),
						txn.set(&etr, &()),
						txn.set(&rtl, &()),
					)?;
				}
				_ => {
					let ltr = graph::new_pointer(ns, db, &l.table, &l.key, Dir::Out, &rid, r);
					let rtl = graph::new_pointer(ns, db, &r.table, &r.key, Dir::In, &rid, l);
					futures::try_join!(
						txn.set(&ltr, &()),
						txn.set(&etl, &()),
						txn.set(&etr, &()),
						txn.set(&rtl, &()),
					)?;
				}
			}



			self.current.doc.to_mut().put(&IN, l.clone().into());
			self.current.doc.to_mut().put(&OUT, r.clone().into());
		}

		Ok(())
	}
}
