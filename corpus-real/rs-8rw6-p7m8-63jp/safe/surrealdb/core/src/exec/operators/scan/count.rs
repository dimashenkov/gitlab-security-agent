















use std::ops::Bound;
use std::sync::Arc;

use tracing::instrument;

use crate::catalog::{DatabaseId, Index, NamespaceId, Permission};
use crate::err::Error;
use crate::exec::operators::scan::index_count::sum_index_count_deltas;
use crate::exec::permission::{
	PhysicalPermission, convert_permission_to_physical_runtime, should_check_perms,
	validate_record_user_access,
};
use crate::exec::{
	AccessMode, CardinalityHint, ContextLevel, EvalContext, ExecOperator, ExecutionContext,
	FlowResult, OperatorMetrics, PhysicalExpr, ValueBatch, ValueBatchStream, monitor_stream,
};
use crate::expr::{ControlFlow, ControlFlowExt};
use crate::iam::Action;
use crate::key::record;
use crate::kvs::{KVKey, KVValue};
use crate::val::{Number, Object, RecordIdKey, TableName, Value};







#[derive(Debug, Clone)]
pub struct CountScan {

	pub(crate) source: Arc<dyn PhysicalExpr>,

	pub(crate) version: Option<Arc<dyn PhysicalExpr>>,



	pub(crate) field_names: Vec<String>,

	pub(crate) metrics: Arc<OperatorMetrics>,
}

impl CountScan {

	pub(crate) fn new(
		source: Arc<dyn PhysicalExpr>,
		version: Option<Arc<dyn PhysicalExpr>>,
		field_names: Vec<String>,
	) -> Self {
		debug_assert!(!field_names.is_empty(), "CountScan requires at least one field name");
		Self {
			source,
			version,
			field_names,
			metrics: Arc::new(OperatorMetrics::new()),
		}
	}
}
impl ExecOperator for CountScan {
	fn name(&self) -> &'static str {
		"CountScan"
	}

	fn attrs(&self) -> Vec<(String, String)> {
		vec![("source".to_string(), self.source.to_sql())]
	}

	fn required_context(&self) -> ContextLevel {

		let exprs_ctx = [Some(&self.source), self.version.as_ref()]
			.into_iter()
			.flatten()
			.map(|e| e.required_context())
			.max()
			.unwrap_or(ContextLevel::Root);
		exprs_ctx.max(ContextLevel::Database)
	}

	fn metrics(&self) -> Option<&OperatorMetrics> {
		Some(&self.metrics)
	}

	fn expressions(&self) -> Vec<(&str, &Arc<dyn PhysicalExpr>)> {
		let mut exprs = vec![("source", &self.source)];
		if let Some(ref version) = self.version {
			exprs.push(("version", version));
		}
		exprs
	}

	fn access_mode(&self) -> AccessMode {


		let version_mode =
			self.version.as_ref().map(|e| e.access_mode()).unwrap_or(AccessMode::ReadOnly);
		self.source.access_mode().combine(version_mode)
	}

	fn cardinality_hint(&self) -> CardinalityHint {
		CardinalityHint::AtMostOne
	}

	#[instrument(name = "CountScan::execute", level = "trace", skip_all)]
	fn execute(&self, ctx: &ExecutionContext) -> FlowResult<ValueBatchStream> {
		let db_ctx = ctx.database()?.clone();
		validate_record_user_access(&db_ctx)?;
		let check_perms = should_check_perms(&db_ctx, Action::View)?;

		let source_expr = Arc::clone(&self.source);
		let version = self.version.clone();
		let field_names = self.field_names.clone();
		let ctx = ctx.clone();

		let stream = async_stream::try_stream! {
			let db_ctx = ctx.database().context("CountScan requires database context")?;
			let txn = ctx.txn();
			let ns = Arc::clone(&db_ctx.ns_ctx.ns);
			let db = Arc::clone(&db_ctx.db);


			let version: Option<u64> = match &version {
				Some(expr) => {
					let eval_ctx = EvalContext::from_exec_ctx(&ctx);
					let v = expr.evaluate(eval_ctx).await?;
					Some(
						v.cast_to::<crate::val::Datetime>()
							.map_err(|e| anyhow::anyhow!("{e}"))?
							.to_version_stamp(txn.timestamp_impl().as_ref())?,
					)
				}
				None => ctx.version_stamp(),
			};


			let eval_ctx = EvalContext::from_exec_ctx(&ctx);
			let table_value = source_expr.evaluate(eval_ctx).await?;

			let (table_name, rid) = match table_value {
				Value::Table(t) => (t, None),
				Value::RecordId(rid) => (rid.table.clone(), Some(rid)),

				_ => {
					Err(ControlFlow::Err(anyhow::anyhow!(
						"CountScan received a non-table source"
					)))?;
					unreachable!()
				}
			};


			let table_def = db_ctx
				.get_table_def(&table_name, version)
				.await
				.context("Failed to get table")?;

			if table_def.is_none() {
				Err(ControlFlow::Err(anyhow::Error::new(Error::TbNotFound {
					name: table_name.clone(),
				})))?;
			}


			let select_permission = if check_perms {
				let catalog_perm = match &table_def {
					Some(def) => def.permissions.select.clone(),
					None => Permission::None,
				};
				convert_permission_to_physical_runtime(&catalog_perm, ctx.ctx())
					.await
					.context("Failed to convert permission")?
			} else {
				PhysicalPermission::Allow
			};

			match select_permission {
				PhysicalPermission::Deny => {

					return;
				}
				PhysicalPermission::Conditional(_) => {




					let count = count_with_perm_fallback(
						&ctx, ns.namespace_id, db.database_id,
						&table_name, rid.as_ref(), version, &select_permission,
					).await?;
					yield make_count_batch(count, &field_names);
					return;
				}
				PhysicalPermission::Allow => {

				}
			}


			let count = if let Some(ref rid) = rid {

				count_range(
					ns.namespace_id, db.database_id, &rid.table,
					&rid.key, &txn, version,
				).await?
			} else {

				let count_from_index = if version.is_none() {
					let indexes = db_ctx
						.get_table_indexes(&table_name, version)
						.await
						.ok();
					if let Some(indexes) = indexes {
						let matching = indexes.iter().find(|ix| {
							matches!(&ix.index, Index::Count(None))
						});
						if let Some(ix_def) = matching {
							sum_index_count_deltas(
								&ctx,
								&txn,
								ns.namespace_id,
								db.database_id,
								&table_name,
								ix_def.index_id,
							).await.ok()
						} else {
							None
						}
					} else {
						None
					}
				} else {
					None
				};

				if let Some(count) = count_from_index {
					count
				} else {

					let beg = record::prefix(ns.namespace_id, db.database_id, &table_name)?;
					let end = record::suffix(ns.namespace_id, db.database_id, &table_name)?;
					txn.count(beg..end, version).await
						.context("Failed to count table records")?
				}
			};

			yield make_count_batch(count, &field_names);
		};

		Ok(monitor_stream(Box::pin(stream), "CountScan", &self.metrics))
	}
}













fn make_count_batch(count: usize, field_names: &[String]) -> ValueBatch {
	let mut obj = Object::default();
	let count_val = Value::Number(Number::Int(count as i64));
	for name in field_names {
		obj.insert(name.clone(), count_val.clone());
	}
	ValueBatch {
		values: vec![Value::Object(obj)],
	}
}


async fn count_range(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	table: &TableName,
	key: &RecordIdKey,
	txn: &crate::kvs::Transaction,
	version: Option<u64>,
) -> Result<usize, ControlFlow> {
	match key {
		RecordIdKey::Range(range) => {
			let beg = range_start_key(ns_id, db_id, table, &range.start)?;
			let end = range_end_key(ns_id, db_id, table, &range.end)?;
			txn.count(beg..end, version).await.context("Failed to count range records")
		}
		_ => {

			let record_key = record::new(ns_id, db_id, table, key);
			let exists = txn
				.exists(&record_key, version)
				.await
				.context("Failed to check record existence")?;
			Ok(usize::from(exists))
		}
	}
}


fn range_start_key(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	table: &TableName,
	bound: &Bound<RecordIdKey>,
) -> Result<crate::kvs::Key, ControlFlow> {
	match bound {
		Bound::Unbounded => {
			record::prefix(ns_id, db_id, table).context("Failed to create prefix key")
		}
		Bound::Included(v) => {
			record::new(ns_id, db_id, table, v).encode_key().context("Failed to create begin key")
		}
		Bound::Excluded(v) => {
			let mut key = record::new(ns_id, db_id, table, v)
				.encode_key()
				.context("Failed to create begin key")?;
			key.push(0x00);
			Ok(key)
		}
	}
}


fn range_end_key(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	table: &TableName,
	bound: &Bound<RecordIdKey>,
) -> Result<crate::kvs::Key, ControlFlow> {
	match bound {
		Bound::Unbounded => {
			record::suffix(ns_id, db_id, table).context("Failed to create suffix key")
		}
		Bound::Excluded(v) => {
			record::new(ns_id, db_id, table, v).encode_key().context("Failed to create end key")
		}
		Bound::Included(v) => {
			let mut key = record::new(ns_id, db_id, table, v)
				.encode_key()
				.context("Failed to create end key")?;
			key.push(0x00);
			Ok(key)
		}
	}
}



async fn count_with_perm_fallback(
	ctx: &ExecutionContext,
	ns_id: NamespaceId,
	db_id: DatabaseId,
	table_name: &TableName,
	rid: Option<&crate::val::RecordId>,
	version: Option<u64>,
	permission: &PhysicalPermission,
) -> Result<usize, ControlFlow> {
	let txn = ctx.txn();


	let (beg, end) = if let Some(rid) = rid {
		match &rid.key {
			RecordIdKey::Range(range) => {
				let beg = range_start_key(ns_id, db_id, &rid.table, &range.start)?;
				let end = range_end_key(ns_id, db_id, &rid.table, &range.end)?;
				(beg, end)
			}
			_ => {

				let Some(value) =
					crate::exec::operators::fetch::fetch_raw_record(ctx, rid, version).await?
				else {
					return Ok(0);
				};
				let allowed = check_perm_value(ctx, &value, permission).await?;
				return Ok(usize::from(allowed));
			}
		}
	} else {
		let beg = record::prefix(ns_id, db_id, table_name)?;
		let end = record::suffix(ns_id, db_id, table_name)?;
		(beg, end)
	};



	let mut cursor = txn
		.open_vals_cursor(beg..end, crate::idx::planner::ScanDirection::Forward, 0, version)
		.await
		.context("Failed to open scan cursor")?;
	let mut count = 0usize;
	loop {
		if ctx.cancellation().is_cancelled() {
			return Err(ControlFlow::Err(anyhow::anyhow!(Error::QueryCancelled)));
		}
		let batch = cursor
			.next_batch(crate::kvs::ScanLimit::Count(crate::kvs::NORMAL_BATCH_SIZE))
			.await
			.context("Failed to scan record")?;
		if batch.is_empty() {
			break;
		}
		for (key, val) in &batch {
			let decoded_key = crate::key::record::RecordKey::decode_key(key)
				.context("Failed to decode record key")?;
			let rid_val = crate::val::RecordId {
				table: decoded_key.tb.into_owned(),
				key: decoded_key.id,
			};
			let record = crate::catalog::Record::kv_decode_value(val, rid_val)
				.context("Failed to deserialize record")?;
			let value = record.data;


			let allowed = match permission {
				PhysicalPermission::Allow => true,
				PhysicalPermission::Deny => false,
				PhysicalPermission::Conditional(expr) => {
					let eval_ctx = EvalContext::from_exec_ctx(ctx).with_value(&value);
					expr.evaluate(eval_ctx).await.map(|v| v.is_truthy()).map_err(|e| {
						ControlFlow::Err(anyhow::anyhow!("Failed to check permission: {e}"))
					})?
				}
			};
			if allowed {
				count += 1;
			}
		}
	}

	Ok(count)
}


async fn check_perm_value(
	ctx: &ExecutionContext,
	value: &Value,
	permission: &PhysicalPermission,
) -> Result<bool, ControlFlow> {
	match permission {
		PhysicalPermission::Allow => Ok(true),
		PhysicalPermission::Deny => Ok(false),
		PhysicalPermission::Conditional(expr) => {
			let eval_ctx = EvalContext::from_exec_ctx(ctx).with_value(value);
			expr.evaluate(eval_ctx)
				.await
				.map(|v| v.is_truthy())
				.map_err(|e| ControlFlow::Err(anyhow::anyhow!("Failed to check permission: {e}")))
		}
	}
}
