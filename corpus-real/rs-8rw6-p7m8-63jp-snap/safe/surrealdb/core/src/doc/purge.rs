use std::sync::Arc;

use anyhow::{Result, bail};
use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use crate::catalog::FieldDefinition;
use crate::catalog::providers::TableProvider;
use crate::ctx::{Context, FrozenContext};
use crate::dbs::Options;
use crate::doc::{CursorDoc, Document};
use crate::err::Error;
use crate::expr::data::Assignment;
use crate::expr::dir::Dir;
use crate::expr::lookup::LookupKind;
use crate::expr::paths::{IN, OUT};
use crate::expr::reference::ReferenceDeleteStrategy;
use crate::expr::statements::{DeleteStatement, UpdateStatement};
use crate::expr::{AssignOperator, Data, Expr, FlowResultExt as _, Idiom, Literal, Lookup, Part};
use crate::idx::planner::ScanDirection;
use crate::key::graph;
use crate::key::r#ref::Ref;
use crate::kvs::{NORMAL_BATCH_SIZE, ScanLimit};
use crate::val::{RecordId, TableName, Value};

impl Document {













	pub(super) async fn purge_record_data(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		if !self.is_modified() {
			return Ok(());
		}

		let txn = ctx.tx();

		if let Some(rid) = self.id.clone() {

			let ns = self.doc_ctx.ns().namespace_id;

			let db = self.doc_ctx.db().database_id;

			txn.del_record(ns, db, &rid.table, &rid.key).await?;


			self.mutated = true;

			if self.initial.doc.is_edge() {
				self.purge_pointers(ctx, rid.as_ref()).await?;
			}

			self.purge_edges(stk, ctx, opt, rid.as_ref()).await?;

			self.purge_references(stk, ctx, opt, rid.as_ref()).await?;
		}

		Ok(())
	}














	async fn purge_pointers(&self, ctx: &FrozenContext, rid: &RecordId) -> Result<()> {

		let txn = ctx.tx();

		let ns = self.doc_ctx.ns().namespace_id;

		let db = self.doc_ctx.db().database_id;

		let l = self.initial.doc.as_ref().pick(&IN);
		let Value::RecordId(ref l) = l else {
			fail!("Expected a record id for the `in` field, found {}", l.to_sql());
		};

		let r = self.initial.doc.as_ref().pick(&OUT);
		let Value::RecordId(ref r) = r else {
			fail!("Expected a record id for the `out` field, found {}", r.to_sql());
		};






















		let etl = graph::new(ns, db, &rid.table, &rid.key, Dir::In, l);
		let etr = graph::new(ns, db, &rid.table, &rid.key, Dir::Out, r);









		let variant = self.initial.doc.edge_variant().unwrap_or_default();

		match variant {
			1 => {
				let ltr = graph::new(ns, db, &l.table, &l.key, Dir::Out, rid);
				let rtl = graph::new(ns, db, &r.table, &r.key, Dir::In, rid);
				futures::try_join!(txn.del(&ltr), txn.del(&etl), txn.del(&etr), txn.del(&rtl))?;
			}
			_ => {
				let ltr = graph::new_pointer(ns, db, &l.table, &l.key, Dir::Out, rid, r);
				let rtl = graph::new_pointer(ns, db, &r.table, &r.key, Dir::In, rid, l);
				futures::try_join!(txn.del(&ltr), txn.del(&etl), txn.del(&etr), txn.del(&rtl))?;
			}
		}

		Ok(())
	}
















	async fn purge_edges(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		rid: &RecordId,
	) -> Result<()> {

		let txn = ctx.tx();

		let ns = self.doc_ctx.ns().namespace_id;

		let db = self.doc_ctx.db().database_id;

		let prefix = crate::key::graph::prefix(ns, db, &rid.table, &rid.key)?;
		let suffix = crate::key::graph::suffix(ns, db, &rid.table, &rid.key)?;

		let mut cursor =
			txn.open_keys_cursor(prefix..suffix, ScanDirection::Forward, 0, None).await?;

		let batch = cursor.next_batch(ScanLimit::Count(1)).await?;

		if !batch.is_empty() {



			let stm = DeleteStatement {
				what: vec![Expr::Idiom(Idiom(vec![
					Part::Start(Expr::Literal(Literal::RecordId(rid.clone().into_literal()))),
					Part::Lookup(Box::new(Lookup {
						kind: LookupKind::Graph(Dir::Both),
						..Default::default()
					})),
				]))],
				..Default::default()
			};






			stm.compute(stk, ctx, opt, None).await?;
		}

		Ok(())
	}



















	async fn purge_references(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		rid: &RecordId,
	) -> Result<()> {

		let txn = ctx.tx();

		let ns = self.doc_ctx.ns().namespace_id;

		let db = self.doc_ctx.db().database_id;

		let prefix = crate::key::r#ref::prefix(ns, db, &rid.table, &rid.key)?;
		let suffix = crate::key::r#ref::suffix(ns, db, &rid.table, &rid.key)?;
		let range = prefix..suffix;

		let mut prev: Option<(TableName, String, Arc<FieldDefinition>)> = None;


		let mut saw_reference_key = false;

		let mut cursor =
			txn.open_keys_cursor(range.clone(), ScanDirection::Forward, 0, None).await?;

		loop {

			let batch = cursor.next_batch(ScanLimit::Count(NORMAL_BATCH_SIZE)).await?;

			if batch.is_empty() {
				break;
			}




			let keys: Vec<Vec<u8>> = batch.iter().map(|k| k.to_vec()).collect();

			for key in keys {
				yield_now!();

				saw_reference_key = true;

				let key = Ref::decode_key(&key)?;

				let ft = key.ft.as_ref();

				let ff = key.ff.as_ref();

				let fd = match prev {

					Some((ref cft, ref cff, ref cfd)) if ft == cft && ff == cff => Arc::clone(cfd),

					_ => {

						let Some(fd) = txn.get_tb_field(ns, db, ft, ff, None).await? else {
							return Err(Error::FdNotFound {
								name: ff.to_string(),
							}
							.into());
						};

						prev = Some((ft.clone(), ff.to_string(), Arc::clone(&fd)));

						fd
					}
				};

				if let Some(reference) = &fd.reference {
					match &reference.on_delete {

						ReferenceDeleteStrategy::Ignore => (),

						ReferenceDeleteStrategy::Reject => {
							let record = RecordId {
								table: key.ft.into_owned(),
								key: key.fk.into_owned(),
							};

							bail!(Error::DeleteRejectedByReference(rid.to_sql(), record.to_sql(),));
						}

						ReferenceDeleteStrategy::Cascade => {
							let record_id = RecordId {
								table: key.ft.into_owned(),
								key: key.fk.into_owned(),
							};


							let stm = DeleteStatement {
								what: vec![Expr::Literal(Literal::RecordId(
									record_id.into_literal(),
								))],
								..DeleteStatement::default()
							};

							stm.compute(stk, ctx, &opt.clone().with_perms(false), None)
								.await

								.map_err(|e| {
									Error::RefsUpdateFailure(rid.to_sql(), e.to_string())
								})?;
						}

						ReferenceDeleteStrategy::Unset => {
							let opt = opt.clone().with_perms(false);
							let record = RecordId {
								table: key.ft.into_owned(),
								key: key.fk.into_owned(),
							};

							if let Some(doc) =
								record.clone().select_document(stk, ctx, &opt, None).await?
							{
								let doc = Value::Object(doc);
								let data = match doc.pick(&fd.name) {
									Value::RecordId(_) => {
										Some(Data::UnsetExpression(vec![fd.name.clone()]))
									}
									Value::Array(_) | Value::Set(_) => {
										Some(Data::SetExpression(vec![Assignment {
											place: fd.name.clone(),
											operator: AssignOperator::Subtract,
											value: Expr::Literal(Literal::RecordId(
												rid.clone().into_literal(),
											)),
										}]))
									}
									Value::None => None,
									v => {
										fail!(
											"Expected either a record id, array, set or none, found {}",
											v.to_sql()
										)
									}
								};

								if data.is_some() {

									let stm = UpdateStatement {
										what: vec![Expr::Literal(Literal::RecordId(
											record.into_literal(),
										))],
										data,
										..UpdateStatement::default()
									};


									stm.compute(stk, ctx, &opt, None)
										.await

										.map_err(|e| {
											Error::RefsUpdateFailure(rid.to_sql(), e.to_string())
										})?;
								}
							}
						}

						ReferenceDeleteStrategy::Custom(v) => {

							let reference = Value::from(rid.clone());

							let this = RecordId {
								table: key.ft.into_owned(),
								key: key.fk.into_owned(),
							};


							let mut ctx = Context::new_child(ctx);
							ctx.add_value("reference", reference.into());
							let ctx = ctx.freeze();


							let opt = opt.clone().with_perms(false);


							let doc = CursorDoc::new(
								Some(Arc::new(this.clone())),
								None,
								Value::RecordId(this),
							);


							stk.run(|stk| v.compute(stk, &ctx, &opt, Some(&doc)))
								.await
								.catch_return()

								.map_err(|e| {
									Error::RefsUpdateFailure(rid.to_sql(), e.to_string())
								})?;
						}
					}
				}
			}
		}




		if saw_reference_key {
			txn.delr(range).await?;
		}

		Ok(())
	}
}
