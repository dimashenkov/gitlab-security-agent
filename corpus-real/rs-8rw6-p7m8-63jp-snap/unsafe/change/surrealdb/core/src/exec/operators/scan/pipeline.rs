













use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::sync::Arc;

use crate::catalog::providers::TableProvider;
use crate::catalog::{DatabaseId, NamespaceId};
use crate::exec::permission::{
	PhysicalPermission, check_permission_for_value, convert_permission_to_physical,
};
use crate::exec::pre_decode_filter::{PreDecodeFilter, PreDecodeFilterOutcome};
use crate::exec::{EvalContext, ExecutionContext, PhysicalExpr, ValueBatch, ValueBatchStream};
use crate::expr::{ControlFlow, ControlFlowExt};
use crate::idx::planner::ScanDirection;
use crate::key::record;
use crate::kvs::{KVKey, KVValue, Transaction};
use crate::val::{RecordIdKey, TableName, Value};



type RawComputedField = (String, Arc<dyn PhysicalExpr>, Option<crate::expr::Kind>, Vec<String>);









pub(crate) struct ScanPipeline {
	permission: PhysicalPermission,
	predicate: Option<Arc<dyn PhysicalExpr>>,
	field_state: FieldState,
	check_perms: bool,

	needs_processing: bool,

	limit: Option<usize>,

	start: usize,

	skipped: usize,

	emitted: usize,
}

impl ScanPipeline {






	pub(crate) fn compute_needs_processing(
		permission: &PhysicalPermission,
		field_state: &FieldState,
		check_perms: bool,
		predicate: Option<&Arc<dyn PhysicalExpr>>,
	) -> bool {
		!matches!(permission, PhysicalPermission::Allow)
			|| !field_state.computed_fields.is_empty()
			|| (check_perms && !field_state.field_permissions.is_empty())
			|| predicate.is_some()
	}









	pub(crate) fn compute_needs_row_filtering(
		permission: &PhysicalPermission,
		predicate: Option<&Arc<dyn PhysicalExpr>>,
	) -> bool {
		!matches!(permission, PhysicalPermission::Allow) || predicate.is_some()
	}

	pub(crate) fn new(
		permission: PhysicalPermission,
		predicate: Option<Arc<dyn PhysicalExpr>>,
		field_state: FieldState,
		check_perms: bool,
		limit: Option<usize>,
		start: usize,
	) -> Self {
		let needs_processing = Self::compute_needs_processing(
			&permission,
			&field_state,
			check_perms,
			predicate.as_ref(),
		);
		Self {
			permission,
			predicate,
			field_state,
			check_perms,
			needs_processing,
			limit,
			start,
			skipped: 0,
			emitted: 0,
		}
	}


	fn has_limit(&self) -> bool {
		self.limit.is_some() || self.start > 0
	}




	pub(crate) async fn process_batch(
		&mut self,
		batch: &mut Vec<Value>,
		ctx: &ExecutionContext,
	) -> Result<bool, ControlFlow> {

		if self.needs_processing {
			filter_and_process_batch(
				batch,
				&self.permission,
				self.predicate.as_ref(),
				ctx,
				&self.field_state,
				self.check_perms,
			)
			.await?;
		}


		if self.has_limit() && !batch.is_empty() {

			if self.skipped < self.start {
				let remaining_to_skip = self.start - self.skipped;
				if batch.len() <= remaining_to_skip {

					self.skipped += batch.len();
					batch.clear();
					return Ok(true);
				}
				self.skipped = self.start;
				batch.drain(..remaining_to_skip);
			}

			if let Some(limit) = self.limit {
				let remaining = limit.saturating_sub(self.emitted);
				if batch.len() > remaining {
					batch.truncate(remaining);
				}
			}
			self.emitted += batch.len();
		}


		Ok(self.limit.is_none_or(|l| self.emitted < l))
	}
}







pub(crate) fn determine_scan_direction(
	order: Option<&crate::expr::order::Ordering>,
) -> ScanDirection {
	use crate::expr::order::Ordering as OrderingType;
	if let Some(OrderingType::Order(order_list)) = order
		&& let Some(first) = order_list.0.first()
		&& !first.direction
		&& first.value.is_id()
	{
		ScanDirection::Backward
	} else {
		ScanDirection::Forward
	}
}


















#[allow(clippy::too_many_arguments)]
pub(crate) fn kv_scan_stream(
	txn: Arc<Transaction>,
	beg: crate::kvs::Key,
	end: crate::kvs::Key,
	version: Option<u64>,
	storage_limit: Option<usize>,
	direction: ScanDirection,
	pre_skip: usize,
	limit_hint: Option<u32>,
	pre_decode_filter: Option<Arc<PreDecodeFilter>>,
) -> ValueBatchStream {
	let skip = pre_skip.min(u32::MAX as usize) as u32;
	let stream = async_stream::try_stream! {
		let mut cursor = txn
			.open_vals_cursor(beg..end, direction, skip, version)
			.await
			.context("Failed to open scan cursor")?;
		let mut first = true;
		let mut yielded: usize = 0;
		loop {






			let mut batch_size = crate::kvs::NORMAL_BATCH_SIZE;
			if first
				&& let Some(h) = limit_hint
			{
				batch_size = batch_size.min(h);
			}
			if let Some(cap) = storage_limit {
				let remaining = cap.saturating_sub(yielded);
				let remaining_u32 = remaining.min(u32::MAX as usize) as u32;
				batch_size = batch_size.min(remaining_u32);
			}
			if batch_size == 0 {
				break;
			}
			let batch = cursor
				.next_batch(crate::kvs::ScanLimit::Count(batch_size))
				.await
				.context("Failed to scan record")?;
			if batch.is_empty() {
				break;
			}
			let mut decoded = Vec::with_capacity(batch.len());




			match &pre_decode_filter {
				Some(pdf) => {
					for (key, val) in &batch {
						if pdf.apply(key, val) == PreDecodeFilterOutcome::Reject {
							continue;
						}
						decoded.push(decode_record(key, val)?);
					}
				}
				None => {
					for (key, val) in &batch {
						decoded.push(decode_record(key, val)?);
					}
				}
			}
			first = false;
			yielded += batch.len();
			if !decoded.is_empty() {
				yield ValueBatch { values: decoded };
			}
		}
	};
	Box::pin(stream)
}


#[inline]
pub(crate) fn decode_record(key: &[u8], val: &[u8]) -> Result<Value, ControlFlow> {
	let decoded_key =
		crate::key::record::RecordKey::decode_key(key).context("Failed to decode record key")?;

	let rid = crate::val::RecordId {
		table: decoded_key.tb.into_owned(),
		key: decoded_key.id,
	};

	let record = crate::catalog::Record::kv_decode_value(val, rid)
		.context("Failed to deserialize record")?;


	Ok(record.data)
}










macro_rules! check_perm {
	($permission:expr, $value:expr, $ctx:expr) => {
		match $permission {
			PhysicalPermission::Allow => Ok::<bool, ControlFlow>(true),
			PhysicalPermission::Deny => Ok(false),
			PhysicalPermission::Conditional(expr) => {



				if $ctx.root().skip_fetch_perms {
					Ok(true)
				} else {
					let mut eval_ctx = EvalContext::from_exec_ctx($ctx).with_value($value);
					eval_ctx.skip_fetch_perms = true;
					expr.evaluate(eval_ctx).await.map(|v| v.is_truthy()).map_err(|e| {
						ControlFlow::Err(anyhow::anyhow!("Failed to check permission: {e}"))
					})
				}
			}
		}
	};
}







pub(crate) async fn filter_and_process_batch(
	batch: &mut Vec<Value>,
	permission: &PhysicalPermission,
	predicate: Option<&Arc<dyn PhysicalExpr>>,
	ctx: &ExecutionContext,
	state: &FieldState,
	check_perms: bool,
) -> Result<(), ControlFlow> {
	let needs_perm_filter = !matches!(permission, PhysicalPermission::Allow);



	if !needs_perm_filter
		&& state.computed_fields.is_empty()
		&& (!check_perms || state.field_permissions.is_empty())
		&& let Some(pred) = predicate
	{
		let eval_ctx = EvalContext::from_exec_ctx(ctx);
		let results = pred.evaluate_batch(eval_ctx, &batch[..]).await?;
		let mut write_idx = 0;
		for (read_idx, result) in results.into_iter().enumerate() {
			if result.is_truthy() {
				if write_idx != read_idx {
					batch.swap(write_idx, read_idx);
				}
				write_idx += 1;
			}
		}
		batch.truncate(write_idx);
		return Ok(());
	}

	let mut write_idx = 0;
	for read_idx in 0..batch.len() {

		if needs_perm_filter && !check_perm!(permission, &batch[read_idx], ctx)? {
			continue;
		}

		if write_idx != read_idx {
			batch.swap(write_idx, read_idx);
		}

		compute_fields_for_value(ctx, state, &mut batch[write_idx], false).await?;



		if check_perms {
			filter_fields_by_permission(ctx, state, &mut batch[write_idx]).await?;
		}

		if let Some(pred) = predicate {
			let eval_ctx = EvalContext::from_exec_ctx(ctx).with_value_and_doc(&batch[write_idx]);
			if !pred.evaluate(eval_ctx).await?.is_truthy() {
				continue;
			}
		}
		write_idx += 1;
	}
	batch.truncate(write_idx);
	Ok(())
}






pub(crate) fn range_start_key(
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


pub(crate) fn range_end_key(
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


pub(crate) async fn eval_limit_expr(
	expr: &dyn PhysicalExpr,
	ctx: &ExecutionContext,
) -> Result<usize, ControlFlow> {
	let eval_ctx = EvalContext::from_exec_ctx(ctx);
	let value = expr
		.evaluate(eval_ctx)
		.await
		.map_err(|e| ControlFlow::Err(anyhow::anyhow!("Failed to evaluate LIMIT/START: {e}")))?;
	match &value {
		Value::Number(n) => {
			let i = (*n).to_int();
			if i >= 0 {
				Ok(i as usize)
			} else {
				Err(ControlFlow::Err(anyhow::anyhow!(
					"LIMIT/START must be a non-negative integer, got {i}"
				)))
			}
		}
		Value::None | Value::Null => Ok(0),
		_ => Err(ControlFlow::Err(anyhow::anyhow!(
			"LIMIT/START must be an integer, got {:?}",
			value
		))),
	}
}











#[derive(Debug, Clone)]
pub(crate) struct FieldState {

	pub(crate) computed_fields: Vec<ComputedFieldDef>,






	pub(crate) field_permissions: Arc<Vec<(crate::expr::Idiom, PhysicalPermission)>>,



	dep_map: Arc<HashMap<String, crate::expr::computed_deps::ComputedDeps>>,









	permission_field_deps: Arc<HashSet<String>>,



	permission_deps_complete: bool,
}

impl FieldState {

	pub(crate) fn empty() -> Self {
		Self {
			computed_fields: Vec::new(),
			field_permissions: Arc::new(Vec::new()),
			dep_map: Arc::new(HashMap::new()),
			permission_field_deps: Arc::new(HashSet::new()),
			permission_deps_complete: true,
		}
	}
}


#[derive(Debug, Clone)]
pub(crate) struct ComputedFieldDef {

	field_name: String,

	expr: Arc<dyn PhysicalExpr>,

	kind: Option<crate::expr::Kind>,
}

impl ComputedFieldDef {

	pub(crate) fn field_name(&self) -> &str {
		&self.field_name
	}
}







pub(crate) async fn build_field_state_raw(
	planner: &crate::exec::planner::Planner<'_>,
	ns_id: crate::catalog::NamespaceId,
	db_id: crate::catalog::DatabaseId,
	table_name: &TableName,
	check_perms: bool,
	version: Option<u64>,
) -> Result<FieldState, ControlFlow> {
	let txn =
		planner.txn().context("build_field_state_raw requires a planner with a transaction")?;
	let field_defs = txn
		.all_tb_fields(ns_id, db_id, table_name, version)
		.await
		.context("Failed to get field definitions")?;




	let has_computed = field_defs.iter().any(|fd| fd.computed.is_some());
	let has_field_perms = check_perms
		&& field_defs
			.iter()
			.any(|fd| !matches!(fd.select_permission, crate::catalog::Permission::Full));
	if !has_computed && !has_field_perms {
		return Ok(FieldState::empty());
	}












	let mut raw_computed: Vec<RawComputedField> = Vec::new();
	let mut dep_map: HashMap<String, crate::expr::computed_deps::ComputedDeps> = HashMap::new();

	for fd in field_defs.iter() {
		if let Some(ref expr) = fd.computed {
			let field_name = fd.name.to_raw_string();

			let deps = if let Some(ref cd) = fd.computed_deps {
				crate::expr::computed_deps::ComputedDeps {
					fields: cd.fields.clone(),
					is_complete: cd.is_complete,
				}
			} else {
				crate::expr::computed_deps::extract_computed_deps(expr)
			};

			dep_map.insert(field_name.clone(), deps.clone());

			let physical_expr = planner.physical_expr(expr.clone()).await.with_context(|| {
				format!("Computed field '{field_name}' has unsupported expression")
			})?;

			raw_computed.push((field_name, physical_expr, fd.field_kind.clone(), deps.fields));
		}
	}


	let topo_input: Vec<(String, Vec<String>)> =
		raw_computed.iter().map(|(name, _, _, deps)| (name.clone(), deps.clone())).collect();
	let sorted_indices = crate::expr::computed_deps::topological_sort_computed_fields(&topo_input);

	let mut computed_fields = Vec::with_capacity(sorted_indices.len());
	for idx in sorted_indices {
		let (field_name, expr, kind, _) = &raw_computed[idx];
		computed_fields.push(ComputedFieldDef {
			field_name: field_name.clone(),
			expr: Arc::clone(expr),
			kind: kind.clone(),
		});
	}












	let mut field_permissions: Vec<(crate::expr::Idiom, PhysicalPermission)> = Vec::new();
	let mut permission_field_deps: HashSet<String> = HashSet::new();
	let mut permission_deps_complete = true;
	if check_perms {
		for fd in field_defs.iter() {
			if matches!(fd.select_permission, crate::catalog::Permission::Full) {
				continue;
			}
			if let crate::catalog::Permission::Specific(ref expr) = fd.select_permission {
				let deps = crate::expr::computed_deps::extract_computed_deps(expr);
				if !deps.is_complete {




					if permission_deps_complete {
						crate::expr::computed_deps::warn_incomplete_perm_deps(
							table_name.as_str(),
							fd.name.to_raw_string().as_str(),
						);
					}
					permission_deps_complete = false;
				}
				permission_field_deps.extend(deps.fields);
			}
			let physical_perm = convert_permission_to_physical(&fd.select_permission, planner)
				.await
				.context("Failed to convert field permission")?;
			field_permissions.push((fd.name.clone(), physical_perm));
		}
	}

	Ok(FieldState {
		computed_fields,
		field_permissions: Arc::new(field_permissions),
		dep_map: Arc::new(dep_map),
		permission_field_deps: Arc::new(permission_field_deps),
		permission_deps_complete,
	})
}








pub(crate) async fn build_field_state(
	ctx: &ExecutionContext,
	table_name: &TableName,
	check_perms: bool,
	needed_fields: Option<&std::collections::HashSet<String>>,
) -> Result<FieldState, ControlFlow> {
	let db_ctx = ctx.database().context("build_field_state requires database context")?;
	let version = ctx.version_stamp();
	let cache_key = (table_name.clone(), check_perms);



	if version.is_none() {
		let cache = db_ctx.field_state_cache.read().await;
		if let Some(cached) = cache.get(&cache_key) {
			return Ok(filter_field_state_for_projection(cached, needed_fields));
		}
	}





	let planner = crate::exec::planner::Planner::for_database(ctx.ctx(), ctx.txn(), db_ctx);
	let full_state = build_field_state_raw(
		&planner,
		db_ctx.ns_ctx.ns.namespace_id,
		db_ctx.db.database_id,
		table_name,
		check_perms,
		version,
	)
	.await?;


	let cached = Arc::new(full_state);
	if version.is_none() {
		db_ctx.field_state_cache.write().await.insert(cache_key, Arc::clone(&cached));
	}


	Ok(filter_field_state_for_projection(&cached, needed_fields))
}














pub(crate) fn filter_field_state_for_projection(
	full_state: &FieldState,
	needed_fields: Option<&std::collections::HashSet<String>>,
) -> FieldState {
	let Some(needed) = needed_fields else {
		return full_state.clone();
	};

	if !full_state.permission_deps_complete {



		return full_state.clone();
	}



	let mut needed_with_perms: std::collections::HashSet<String> = needed.clone();
	needed_with_perms.extend(full_state.permission_field_deps.iter().cloned());

	let required = crate::expr::computed_deps::resolve_required_computed_fields(
		&needed_with_perms,
		&full_state.dep_map,
	);

	let computed_fields = if let Some(ref required_set) = required {
		full_state
			.computed_fields
			.iter()
			.filter(|cf| required_set.contains(&cf.field_name))
			.cloned()
			.collect()
	} else {
		full_state.computed_fields.clone()
	};

	FieldState {
		computed_fields,
		field_permissions: Arc::clone(&full_state.field_permissions),
		dep_map: Arc::clone(&full_state.dep_map),
		permission_field_deps: Arc::clone(&full_state.permission_field_deps),
		permission_deps_complete: full_state.permission_deps_complete,
	}
}








pub(crate) async fn compute_fields_for_value(
	ctx: &ExecutionContext,
	state: &FieldState,
	value: &mut Value,
	skip_fetch_perms: bool,
) -> Result<(), ControlFlow> {
	if state.computed_fields.is_empty() {
		return Ok(());
	}

	let mut eval_ctx = EvalContext::from_exec_ctx(ctx);
	eval_ctx.skip_fetch_perms = skip_fetch_perms;




	eval_ctx.computing_record = match &*value {
		Value::Object(obj) => match obj.get("id") {
			Some(Value::RecordId(rid)) => Some(rid.clone()),
			_ => None,
		},
		_ => None,
	};

	for cf in &state.computed_fields {


		let row_ctx = eval_ctx.with_value_and_doc(value);
		let computed_value = match cf.expr.evaluate(row_ctx).await {
			Ok(v) => v,
			Err(ControlFlow::Return(v)) => v,
			Err(e) => return Err(e),
		};


		let final_value = if let Some(kind) = &cf.kind {
			computed_value
				.coerce_to_kind(kind)
				.with_context(|| format!("Failed to coerce computed field '{}'", cf.field_name))?
		} else {
			computed_value
		};


		if let Value::Object(obj) = value {
			obj.insert(cf.field_name.clone(), final_value);
		} else {
			return Err(ControlFlow::Err(anyhow::anyhow!("Value is not an object: {:?}", value)));
		}
	}

	Ok(())
}








pub(crate) async fn filter_fields_by_permission(
	ctx: &ExecutionContext,
	state: &FieldState,
	value: &mut Value,
) -> Result<(), ControlFlow> {
	if state.field_permissions.is_empty() {
		return Ok(());
	}
	if !matches!(value, Value::Object(_)) {
		return Ok(());
	}





	let mut snapshot: Option<Value> = None;
	for (idiom, perm) in state.field_permissions.iter() {
		match perm {
			PhysicalPermission::Allow => continue,
			PhysicalPermission::Deny => {
				let original = snapshot.get_or_insert_with(|| value.clone());
				for path in original.each(&idiom.0) {
					value.cut(&path.0);
				}
			}
			PhysicalPermission::Conditional(_) => {
				let original = snapshot.get_or_insert_with(|| value.clone());
				for path in original.each(&idiom.0) {
					let field_value = original.pick(&path.0);
					let allowed =
						check_permission_for_value(perm, original, Some(&field_value), ctx)
							.await
							.map_err(|e| {
							ControlFlow::Err(anyhow::anyhow!(
								"Failed to check field permission: {e}"
							))
						})?;
					if !allowed {
						value.cut(&path.0);
					}
				}
			}
		}
	}

	Ok(())
}
