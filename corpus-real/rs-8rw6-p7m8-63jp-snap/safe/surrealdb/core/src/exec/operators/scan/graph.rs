





use std::ops::Bound;
use std::sync::Arc;

use futures::StreamExt;

use super::common::{
	evaluate_bound_key, extract_record_ids_into, resolve_record_batch, resolve_version_stamp,
};
use crate::catalog::{DatabaseId, NamespaceId};
use crate::exec::parts::LookupDirection;
use crate::exec::permission::{PhysicalPermission, should_check_perms};
use crate::exec::{
	AccessMode, ContextLevel, ControlFlowExt, ExecOperator, ExecutionContext, FlowResult,
	OperatorMetrics, PhysicalExpr, ValueBatch, ValueBatchStream, buffer_stream, monitor_stream,
};
use crate::expr::{ControlFlow, Dir};
use crate::iam::Action;
use crate::idx::planner::ScanDirection;
use crate::kvs::{CachePolicy, KVKey};
use crate::val::{RecordId, TableName};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraphScanOutput {

	#[default]
	TargetId,

	FullEdge,







	TargetVertex,
}





#[derive(Debug, Clone)]
pub struct EdgeTableSpec {

	pub table: TableName,

	pub range_start: Bound<Arc<dyn PhysicalExpr>>,

	pub range_end: Bound<Arc<dyn PhysicalExpr>>,
}












#[derive(Debug, Clone)]
pub struct GraphEdgeScan {

	pub(crate) input: Arc<dyn ExecOperator>,


	pub(crate) direction: LookupDirection,



	pub(crate) edge_tables: Vec<EdgeTableSpec>,


	pub(crate) output_mode: GraphScanOutput,











	pub(crate) target_tables: Vec<TableName>,


	pub(crate) version: Option<Arc<dyn PhysicalExpr>>,



	pub(crate) limit: Option<usize>,


	pub(crate) metrics: Arc<OperatorMetrics>,
}

impl GraphEdgeScan {
	pub(crate) fn new(
		input: Arc<dyn ExecOperator>,
		direction: LookupDirection,
		edge_tables: Vec<EdgeTableSpec>,
		output_mode: GraphScanOutput,
		version: Option<Arc<dyn PhysicalExpr>>,
	) -> Self {
		Self {
			input,
			direction,
			edge_tables,
			output_mode,
			target_tables: Vec::new(),
			version,
			limit: None,
			metrics: Arc::new(OperatorMetrics::new()),
		}
	}

	pub(crate) fn with_limit(mut self, limit: usize) -> Self {
		self.limit = Some(limit);
		self
	}



	pub(crate) fn with_target_tables(mut self, tables: Vec<TableName>) -> Self {
		self.target_tables = tables;
		self
	}
}
impl ExecOperator for GraphEdgeScan {
	fn name(&self) -> &'static str {
		"GraphEdgeScan"
	}

	fn attrs(&self) -> Vec<(String, String)> {
		let dir = match self.direction {
			LookupDirection::Out => "->",
			LookupDirection::In => "<-",
			LookupDirection::Both => "<->",
			LookupDirection::Reference => "<~",
		};
		let tables = if self.edge_tables.is_empty() {
			"*".to_string()
		} else {
			self.edge_tables.iter().map(|t| t.table.as_str()).collect::<Vec<_>>().join(", ")
		};
		let mut attrs = vec![
			("direction".to_string(), dir.to_string()),
			("tables".to_string(), tables),
			("output".to_string(), format!("{:?}", self.output_mode)),
		];
		if let Some(ref version) = self.version {
			attrs.push(("version".to_string(), version.to_sql()));
		}
		if let Some(limit) = self.limit {
			attrs.push(("limit".to_string(), limit.to_string()));
		}
		attrs
	}

	fn required_context(&self) -> ContextLevel {

		self.input.required_context().max(ContextLevel::Database)
	}

	fn access_mode(&self) -> AccessMode {
		let mut mode = self.input.access_mode();
		if let Some(ref version) = self.version {
			mode = mode.combine(version.access_mode());
		}
		mode
	}

	fn metrics(&self) -> Option<&OperatorMetrics> {
		Some(&self.metrics)
	}

	fn children(&self) -> Vec<&Arc<dyn ExecOperator>> {
		vec![&self.input]
	}

	fn execute(&self, ctx: &ExecutionContext) -> FlowResult<ValueBatchStream> {
		let db_ctx = ctx.database()?.clone();






		let check_perms = should_check_perms(&db_ctx, Action::View)?;
		let input_stream = buffer_stream(
			self.input.execute(ctx)?,
			self.input.access_mode(),
			self.input.cardinality_hint(),
			ctx.root().ctx.config.operator_buffer_size,
		);
		let direction = self.direction;
		let edge_tables = self.edge_tables.clone();
		let output_mode = self.output_mode;
		let target_tables = self.target_tables.clone();
		let edge_limit = self.limit;
		let version_expr = self.version.clone();
		let scan_batch_size = ctx.root().ctx.config.scan_batch_size;
		let ctx = ctx.clone();
		let fetch_full = output_mode == GraphScanOutput::FullEdge;

		let stream = async_stream::try_stream! {
			let txn = ctx.txn();
			let ns_id = db_ctx.ns_ctx.ns.namespace_id;
			let db_id = db_ctx.db.database_id;



			let mut perm_cache: std::collections::HashMap<
				crate::val::TableName,
				PhysicalPermission,
			> = std::collections::HashMap::new();

			let version: Option<u64> = resolve_version_stamp(&ctx, version_expr.as_ref()).await?;



			let directions: Vec<Dir> = match direction {
				LookupDirection::Out => vec![Dir::Out],
				LookupDirection::In => vec![Dir::In],
				LookupDirection::Both => vec![Dir::In, Dir::Out],
				LookupDirection::Reference => {
					Err(ControlFlow::Err(anyhow::anyhow!(
						"Reference lookups should use ReferenceScan, not GraphEdgeScan"
					)))?
				}
			};


			futures::pin_mut!(input_stream);
			let mut rid_batch: Vec<RecordId> = Vec::with_capacity(scan_batch_size);

			while let Some(batch_result) = input_stream.next().await {
				let batch = batch_result?;
				let source_rids: Vec<RecordId> = batch.values
					.into_iter()
					.flat_map(|v| {
						let mut rids = Vec::new();
						extract_record_ids_into(v, &mut rids);
						rids
					})
					.collect();


				for rid in &source_rids {
					let mut edges_yielded: usize = 0;
					'dir_loop: for &dir in &directions {
						let ranges = compute_graph_ranges(
							ns_id, db_id, rid, dir, &edge_tables, &ctx,
						).await?;

						for (beg, end) in ranges {










							let mut current_beg = beg;
							let mut limit_hit = false;
							'range_chunks: loop {
								let mut legacy_edges: Vec<RecordId> = Vec::new();
								let mut chunk_bound_hit = false;
								let mut last_processed_key: Option<Vec<u8>> = None;
								{
									let mut cursor = txn
										.open_keys_cursor(
											current_beg.clone()..end.clone(),
											ScanDirection::Forward,
											0,
											version,
										)
										.await
										.context("Failed to open graph cursor")?;
									'cursor_loop: loop {



										let remaining = edge_limit.map(|l| {
											l.saturating_sub(edges_yielded)
												.min(crate::kvs::NORMAL_BATCH_SIZE as usize)
										});
										let batch_size = remaining
											.map(|r| r as u32)
											.unwrap_or(crate::kvs::NORMAL_BATCH_SIZE);
										if batch_size == 0 {
											limit_hit = true;
											break;
										}
										let batch = cursor
											.next_batch(crate::kvs::ScanLimit::Count(batch_size))
											.await
											.context("Failed to scan graph edge")?;
										if batch.is_empty() {
											break;
										}
										for key in &batch {
											let decoded = decode_graph_edge(key)?;
											if output_mode == GraphScanOutput::TargetVertex {
												match decoded.target {



													Some(target)
														if target_tables.is_empty()
															|| target_tables
																.contains(&target.table) =>
													{
														rid_batch.push(target);
														edges_yielded += 1;
													}
													Some(_) => {



													}
													None => {








														legacy_edges.push(decoded.edge);
														if legacy_edges.len()
															>= scan_batch_size
														{
															chunk_bound_hit = true;
															last_processed_key =
																Some(key.to_vec());
															break;
														}
													}
												}
											} else {



												rid_batch.push(decoded.edge);
												edges_yielded += 1;
											}
											if edge_limit.is_some_and(|l| edges_yielded >= l) {
												limit_hit = true;
												break;
											}
										}







										if rid_batch.len() >= scan_batch_size {
											let values = resolve_record_batch(
												&ctx,
												&txn,
												ns_id,
												db_id,
												&rid_batch,
												fetch_full,
												check_perms,
												version,
												CachePolicy::ReadWrite,
												&mut perm_cache,
											)
											.await?;
											yield ValueBatch {
												values,
											};
											rid_batch.clear();
										}
										if limit_hit || chunk_bound_hit {
											break 'cursor_loop;
										}
									}
									drop(cursor);
								}







								if !legacy_edges.is_empty() && !limit_hit {
									let inner_specs: Vec<EdgeTableSpec> =
										if target_tables.is_empty() {
											Vec::new()
										} else {
											target_tables
												.iter()
												.cloned()
												.map(|t| EdgeTableSpec {
													table: t,
													range_start: std::ops::Bound::Unbounded,
													range_end: std::ops::Bound::Unbounded,
												})
												.collect()
										};
									'legacy_loop: for edge_rid in legacy_edges {
										let inner_ranges = compute_graph_ranges(
											ns_id,
											db_id,
											&edge_rid,
											dir,
											&inner_specs,
											&ctx,
										)
										.await?;
										for (ibeg, iend) in inner_ranges {
											let mut inner_cursor = txn
												.open_keys_cursor(
													ibeg..iend,
													ScanDirection::Forward,
													0,
													version,
												)
												.await
												.context(
													"Failed to open legacy-fallback graph cursor",
												)?;
											loop {
												let inner_batch = inner_cursor
													.next_batch(crate::kvs::ScanLimit::Count(
														crate::kvs::NORMAL_BATCH_SIZE,
													))
													.await
													.context(
														"Failed to scan edge adjacency for legacy graph fallback",
													)?;
												if inner_batch.is_empty() {
													break;
												}
												for ik in &inner_batch {







													let endpoint = decode_graph_edge(ik)?.edge;
													rid_batch.push(endpoint);
													edges_yielded += 1;
													if edge_limit
														.is_some_and(|l| edges_yielded >= l)
													{
														limit_hit = true;
														break;
													}
												}
												if rid_batch.len() >= scan_batch_size {
													let values = resolve_record_batch(
														&ctx,
														&txn,
														ns_id,
														db_id,
														&rid_batch,
														fetch_full,
														check_perms,
														version,
														CachePolicy::ReadWrite,
														&mut perm_cache,
													)
													.await?;
													yield ValueBatch {
														values,
													};
													rid_batch.clear();
												}
												if limit_hit {
													break;
												}
											}
											drop(inner_cursor);
											if limit_hit {
												break 'legacy_loop;
											}
										}
									}
								}







								if !chunk_bound_hit || limit_hit {
									break 'range_chunks;
								}
								let mut next_beg = last_processed_key
									.expect("chunk_bound_hit implies a key was processed");
								next_beg.push(0xff);
								current_beg = next_beg;
							}

							if limit_hit {
								break 'dir_loop;
							}
						}
					}
				}
			}


			if !rid_batch.is_empty() {
				let values = resolve_record_batch(
					&ctx, &txn, ns_id, db_id, &rid_batch, fetch_full, check_perms, version,
					CachePolicy::ReadWrite, &mut perm_cache,
				).await?;
				yield ValueBatch { values };
			}
		};

		Ok(monitor_stream(Box::pin(stream), "GraphEdgeScan", &self.metrics))
	}
}










async fn compute_graph_ranges(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	rid: &RecordId,
	dir: Dir,
	edge_tables: &[EdgeTableSpec],
	ctx: &ExecutionContext,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ControlFlow> {
	if edge_tables.is_empty() {

		let beg = crate::key::graph::egprefix(ns_id, db_id, &rid.table, &rid.key, dir)
			.context("Failed to create graph prefix")?;
		let end = crate::key::graph::egsuffix(ns_id, db_id, &rid.table, &rid.key, dir)
			.context("Failed to create graph suffix")?;
		Ok(vec![(beg, end)])
	} else {
		let mut ranges = Vec::with_capacity(edge_tables.len());
		for spec in edge_tables {
			let beg =
				eval_graph_bound(ns_id, db_id, rid, dir, &spec.table, &spec.range_start, true, ctx)
					.await?;
			let end =
				eval_graph_bound(ns_id, db_id, rid, dir, &spec.table, &spec.range_end, false, ctx)
					.await?;
			ranges.push((beg, end));
		}
		Ok(ranges)
	}
}

















#[allow(clippy::too_many_arguments)]
async fn eval_graph_bound(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	rid: &RecordId,
	dir: Dir,
	edge_table: &TableName,
	bound: &Bound<Arc<dyn PhysicalExpr>>,
	is_start: bool,
	ctx: &ExecutionContext,
) -> Result<Vec<u8>, ControlFlow> {
	match bound {
		Bound::Unbounded => {
			if is_start {
				crate::key::graph::ftprefix(ns_id, db_id, &rid.table, &rid.key, dir, edge_table)
					.context("Failed to create graph table prefix")
			} else {
				crate::key::graph::ftsuffix(ns_id, db_id, &rid.table, &rid.key, dir, edge_table)
					.context("Failed to create graph table suffix")
			}
		}
		Bound::Included(expr) => {
			let fk = evaluate_bound_key(expr, ctx).await?;
			let mut key = encode_graph_key(ns_id, db_id, rid, dir, edge_table, fk)?;



			if !is_start {
				key.push(0xff);
			}
			Ok(key)
		}
		Bound::Excluded(expr) => {
			let fk = evaluate_bound_key(expr, ctx).await?;
			let mut key = encode_graph_key(ns_id, db_id, rid, dir, edge_table, fk)?;



			if is_start {
				key.push(0xff);
			}
			Ok(key)
		}
	}
}


fn encode_graph_key(
	ns_id: NamespaceId,
	db_id: DatabaseId,
	rid: &RecordId,
	dir: Dir,
	edge_table: &TableName,
	fk: crate::val::RecordIdKey,
) -> Result<Vec<u8>, ControlFlow> {
	crate::key::graph::new(
		ns_id,
		db_id,
		&rid.table,
		&rid.key,
		dir,
		&RecordId {
			table: edge_table.clone(),
			key: fk,
		},
	)
	.encode_key()
	.context("Failed to encode graph range key")
}







fn decode_graph_edge(key: &[u8]) -> Result<crate::key::graph::DecodedGraph, ControlFlow> {
	crate::key::graph::Graph::decode_key(key).context("Failed to decode graph key")
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::exec::operators::CurrentValueSource;

	#[test]
	fn test_graph_edge_scan_attrs() {
		let scan = GraphEdgeScan::new(
			Arc::new(CurrentValueSource::new()),
			LookupDirection::Out,
			vec![
				EdgeTableSpec {
					table: "knows".into(),
					range_start: Bound::Unbounded,
					range_end: Bound::Unbounded,
				},
				EdgeTableSpec {
					table: "follows".into(),
					range_start: Bound::Unbounded,
					range_end: Bound::Unbounded,
				},
			],
			GraphScanOutput::TargetId,
			None,
		);

		assert_eq!(scan.name(), "GraphEdgeScan");
		let attrs = scan.attrs();
		assert!(attrs.iter().any(|(k, v)| k == "direction" && v == "->"));
		assert!(attrs.iter().any(|(k, v)| k == "tables" && v.contains("knows")));
	}
}
