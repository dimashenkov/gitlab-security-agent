use std::sync::Arc;

use anyhow::{Result, bail};
use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use crate::catalog::aggregation::{self, AggregateFields, AggregationAnalysis, AggregationStat};
use crate::catalog::providers::TableProvider;
use crate::catalog::{Metadata, Record, RecordType, ViewDefinition};
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::{Action, CursorDoc, Document, DocumentContext, Extras, NsDbCtx};
use crate::err::Error;
use crate::expr::field::Selector;
use crate::expr::statements::SelectStatement;
use crate::expr::{
	BinaryOperator, Cond, Expr, Fields, FlowResultExt as _, Function, FunctionCall, Groups, Literal,
};
use crate::idx::planner::RecordStrategy;
use crate::key;
use crate::val::{Array, Number, RecordId, RecordIdKey, TableName, TryAdd, TryMul, TryPow, Value};
struct Recalculation {
	function: String,
	stat: usize,
	arg: usize,
}

impl Document {





	pub(super) async fn process_table_views(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		action: Action,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}
		if !self.is_modified() {
			return Ok(());
		}

		self.process_views(stk, ctx, opt, action).await
	}

	async fn process_views(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		act: Action,
	) -> Result<()> {

		let fts = self.doc_ctx.ft()?;

		let opt = &opt.new_with_perms(false);

		for ft in fts.iter() {

			let Some(tb) = ft.view.as_ref() else {
				fail!("Table stored as view table did not have a view");
			};

			self.process_view(stk, ctx, opt, &ft.name, tb, act).await?;
		}
		Ok(())
	}


	async fn process_view(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		table_name: &TableName,
		view: &ViewDefinition,
		action: Action,
	) -> Result<()> {
		match view {
			ViewDefinition::Select {
				..
			} => {


				Ok(())
			}
			ViewDefinition::Materialized {
				fields,
				condition,
				..
			} => {

				let id = &self.id()?.key;

				let set = if let Some(cond) = condition {
					stk.run(|stk| cond.compute(stk, ctx, opt, Some(&self.current)))
						.await
						.catch_return()?
						.is_truthy()
				} else {
					action != Action::Delete
				};

				let db = self.doc_ctx.db();

				if set {
					let data = fields.compute(stk, ctx, opt, Some(&self.current)).await?;
					let record = Arc::new(Record::new(data));

					ctx.tx()
						.set_record(db.namespace_id, db.database_id, table_name, id, record)
						.await?;
				} else {
					ctx.tx().del_record(db.namespace_id, db.database_id, table_name, id).await?;
				}
				Ok(())
			}
			ViewDefinition::Aggregated {
				analysis,
				condition,
				..
			} => {
				self.process_aggregate_view(stk, ctx, opt, table_name, analysis, condition, action)
					.await
			}
		}
	}


	#[allow(clippy::too_many_arguments)]
	async fn process_aggregate_view(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		view_table_name: &TableName,
		aggr: &AggregationAnalysis,
		condition: &Option<Expr>,
		action: Action,
	) -> Result<()> {
		match action {
			Action::Create => {
				if let Some(cond) = condition
					&& !cond
						.compute(stk, ctx, opt, Some(&self.current))
						.await
						.catch_return()?
						.is_truthy()
				{

					return Ok(());
				}

				let mut group = Vec::with_capacity(aggr.group_expressions.len());
				for g in aggr.group_expressions.iter() {
					group.push(g.compute(stk, ctx, opt, Some(&self.current)).await.catch_return()?);
				}

				self.process_view_record_create(stk, ctx, opt, group, view_table_name, aggr)
					.await?;
			}
			Action::Update => {
				let before_cond = if let Some(cond) = condition {
					cond.compute(stk, ctx, opt, Some(&self.initial))
						.await
						.catch_return()?
						.is_truthy()
				} else {
					true
				};

				let group_before = if before_cond {
					let mut group = Vec::with_capacity(aggr.group_expressions.len());
					for g in aggr.group_expressions.iter() {
						group.push(
							g.compute(stk, ctx, opt, Some(&self.initial)).await.catch_return()?,
						);
					}
					Some(group)
				} else {
					None
				};

				let after_cond = if let Some(cond) = condition {
					cond.compute(stk, ctx, opt, Some(&self.current))
						.await
						.catch_return()?
						.is_truthy()
				} else {
					true
				};

				let group_after = if after_cond {
					let mut group = Vec::with_capacity(aggr.group_expressions.len());
					for g in aggr.group_expressions.iter() {
						group.push(
							g.compute(stk, ctx, opt, Some(&self.current)).await.catch_return()?,
						);
					}
					Some(group)
				} else {
					None
				};

				match (group_before, group_after) {

					(None, None) => {}
					(Some(before), Some(after)) => {
						if before != after {


							self.process_view_record_delete(
								stk,
								ctx,
								opt,
								before,
								view_table_name,
								aggr,
							)
							.await?;
							self.process_view_record_create(
								stk,
								ctx,
								opt,
								after,
								view_table_name,
								aggr,
							)
							.await?;
						} else {
							self.process_view_record_update(
								stk,
								ctx,
								opt,
								before,
								view_table_name,
								aggr,
							)
							.await?;
						}
					}
					(Some(before), None) => {
						self.process_view_record_delete(
							stk,
							ctx,
							opt,
							before,
							view_table_name,
							aggr,
						)
						.await?;
					}
					(None, Some(after)) => {
						self.process_view_record_create(
							stk,
							ctx,
							opt,
							after,
							view_table_name,
							aggr,
						)
						.await?;
					}
				}
			}
			Action::Delete => {
				if let Some(cond) = condition
					&& !cond
						.compute(stk, ctx, opt, Some(&self.initial))
						.await
						.catch_return()?
						.is_truthy()
				{

					return Ok(());
				}

				let mut group = Vec::with_capacity(aggr.group_expressions.len());
				for g in aggr.group_expressions.iter() {
					group.push(g.compute(stk, ctx, opt, Some(&self.initial)).await.catch_return()?);
				}

				self.process_view_record_delete(stk, ctx, opt, group, view_table_name, aggr)
					.await?;
			}
		}

		Ok(())
	}



	async fn process_view_record_create(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		group: Vec<Value>,
		view_table_name: &TableName,
		aggr: &AggregationAnalysis,
	) -> Result<()> {
		let db = self.doc_ctx.db();

		let key = RecordIdKey::Array(Array(group.clone()));
		let tx = ctx.tx();

		let k = key::record::new(db.namespace_id, db.database_id, view_table_name, &key);
		let mut action = Action::Update;
		let mut record = if let Some(bytes) = tx.get_raw(&k, None).await? {







			revision::from_slice::<Record>(&bytes)?
		} else {
			action = Action::Create;
			Record {
				data: Value::None,
				metadata: Some(Metadata {
					record_type: RecordType::Table,
					aggregation_stats: aggr.aggregations.iter().map(|x| x.to_stat()).collect(),
				}),
			}
		};

		let record_before = record.clone();

		let Some(meta) = record.metadata.as_mut() else {
			fail!("Record for a view table had no valid metadata")
		};

		let mut args = Vec::with_capacity(aggr.aggregate_arguments.len());
		for a in aggr.aggregate_arguments.iter() {
			args.push(a.compute(stk, ctx, opt, Some(&self.current)).await.catch_return()?)
		}

		aggregation::add_to_aggregation_stats(&args, &mut meta.aggregation_stats)?;

		let doc =
			Value::Object(aggregation::create_field_document(&group, &meta.aggregation_stats))
				.into();

		let mut data = Value::empty_object();

		match &aggr.fields {
			AggregateFields::Value(_) => {
				fail!("Value selectors are not supported on views");
			}
			AggregateFields::Fields(items) => {
				for (name, expr) in items {
					let res = stk
						.run(|stk| expr.compute(stk, ctx, opt, Some(&doc)))
						.await
						.catch_return()?;
					data.set(stk, ctx, opt, name.as_ref(), res).await?;
				}
			}
		};

		record.data = data;
		let record = Arc::new(record);

		tx.set_record(db.namespace_id, db.database_id, view_table_name, &key, Arc::clone(&record))
			.await?;

		let id = Arc::new(RecordId {
			table: view_table_name.clone(),
			key,
		});

		let ns = self.doc_ctx.ns();
		let db = self.doc_ctx.db();

		let tb = ctx
			.tx()
			.get_or_add_tb(Some(ctx), &ns.name, &db.name, view_table_name, opt.version)
			.await?;
		let parent = NsDbCtx {
			ns: Arc::clone(ns),
			db: Arc::clone(db),
		};
		let doc_ctx =
			DocumentContext::initialise(ctx, &parent, tb, view_table_name, opt.version, true)
				.await?;

		Self::run_triggers(
			stk,
			ctx,
			opt,
			doc_ctx,
			id,
			action,
			Some(record_before.into()),
			Some(record),
		)
		.await?;

		Ok(())
	}



	async fn process_view_record_delete(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		group: Vec<Value>,
		view_table_name: &TableName,
		aggr: &AggregationAnalysis,
	) -> Result<()> {
		let db = self.doc_ctx.db();

		let key = RecordIdKey::Array(Array(group.clone()));
		let tx = ctx.tx();

		let k = key::record::new(db.namespace_id, db.database_id, view_table_name, &key);



		let mut record = if let Some(bytes) = tx.get_raw(&k, None).await? {
			revision::from_slice::<Record>(&bytes)?
		} else {
			fail!("Deletion for a view but no record exists for that view")
		};

		let record_before = record.clone();

		let Some(meta) = record.metadata.as_mut() else {
			fail!("Record for a view table had no valid metadata")
		};

		let Some(count) = AggregationStat::get_count(&meta.aggregation_stats) else {
			fail!("Metadata for view table had no valid count")
		};

		if count == 1 {

			tx.del(&k).await?;

			let ns = self.doc_ctx.ns();
			let db = self.doc_ctx.db();

			let tb = ctx
				.tx()
				.get_or_add_tb(Some(ctx), &ns.name, &db.name, view_table_name, opt.version)
				.await?;
			let parent = NsDbCtx {
				ns: Arc::clone(ns),
				db: Arc::clone(db),
			};
			let doc_ctx =
				DocumentContext::initialise(ctx, &parent, tb, view_table_name, opt.version, true)
					.await?;

			let id = RecordId {
				table: view_table_name.clone(),
				key,
			};

			Self::run_triggers(
				stk,
				ctx,
				opt,
				doc_ctx,
				id.into(),
				Action::Delete,
				Some(record.into()),
				None,
			)
			.await?;
			return Ok(());
		}

		let mut args = Vec::with_capacity(aggr.aggregate_arguments.len());
		for a in aggr.aggregate_arguments.iter() {
			args.push(a.compute(stk, ctx, opt, Some(&self.initial)).await.catch_return()?)
		}

		let mut recalculations = Vec::new();
		for (idx, a) in meta.aggregation_stats.iter_mut().enumerate() {
			match a {
				AggregationStat::Count {
					count,
				} => {
					*count -= 1;
				}
				AggregationStat::CountValue {
					arg,
					count,
				} => {
					if args[*arg].is_truthy() {
						*count -= 1;
					}
				}
				AggregationStat::NumberMax {
					arg,
					max,
				} => {
					let Value::Number(n) = &args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					if *n == *max {


						recalculations.push(Recalculation {
							function: "math::max".to_string(),
							stat: idx,
							arg: *arg,
						})
					}
				}
				AggregationStat::NumberMin {
					arg,
					min,
				} => {
					let Value::Number(n) = &args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					if *n == *min {
						recalculations.push(Recalculation {
							function: "math::min".to_string(),
							stat: idx,
							arg: *arg,
						})
					}
				}
				AggregationStat::Sum {
					arg,
					sum,
				} => {
					let Value::Number(n) = &args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*sum = *sum - *n;
				}
				AggregationStat::Mean {
					arg,
					sum,
					count,
				} => {
					let Value::Number(n) = &args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*sum = *sum - *n;
					*count -= 1;
				}
				AggregationStat::TimeMax {
					arg,
					max,
				} => {
					let Value::Datetime(n) = &args[*arg] else {
						fail!("Old record wasn't a datetime but was created with a number");
					};

					if *n == *max {
						recalculations.push(Recalculation {
							function: "time::max".to_string(),
							stat: idx,
							arg: *arg,
						});
					}
				}
				AggregationStat::TimeMin {
					arg,
					min,
				} => {
					let Value::Datetime(n) = &args[*arg] else {
						fail!("Old record wasn't a datetime but was created with a number");
					};

					if *n == *min {
						recalculations.push(Recalculation {
							function: "time::min".to_string(),
							stat: idx,
							arg: *arg,
						});
					}
				}
				AggregationStat::Variance {
					arg,
					sum,
					sum_of_squares,
					count,
				}
				| AggregationStat::StdDev {
					arg,
					sum,
					sum_of_squares,
					count,
				} => {
					let Value::Number(n) = &args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*count -= 1;
					*sum = *sum - *n;
					*sum_of_squares = *sum_of_squares - n.try_pow(Number::from(2))?;
				}
				AggregationStat::Accumulate {
					..
				} => fail!("Accumulate aggregation is not supported in materialized views"),
			}
		}

		if !recalculations.is_empty() {

			let exprs = recalculations
				.iter()
				.map(|x| {
					Expr::FunctionCall(Box::new(FunctionCall {
						receiver: Function::Normal(x.function.clone()),
						arguments: vec![aggr.aggregate_arguments[x.arg].clone()],
					}))
				})
				.collect();


			let mut condition = None;
			for (idx, g) in aggr.group_expressions.iter().enumerate() {
				let expr = Expr::Binary {
					left: Box::new(g.clone()),
					op: BinaryOperator::Equal,
					right: Box::new(group[idx].clone().into_literal()),
				};
				if let Some(c) = condition {
					condition = Some(Expr::Binary {
						left: Box::new(c),
						op: BinaryOperator::And,
						right: Box::new(expr),
					})
				} else {
					condition = Some(expr)
				}
			}

			let table_name = self.id()?.table.clone();

			let recalc_stmt = SelectStatement {

				fields: Fields::Value(Box::new(Selector {
					expr: Expr::Literal(Literal::Array(exprs)),
					alias: None,
				})),

				only: true,
				what: vec![Expr::Table(table_name.clone())],

				cond: condition.map(Cond),

				group: Some(Groups(Vec::new())),
				omit: vec![],
				with: None,
				split: None,
				order: None,
				limit: None,
				start: None,
				fetch: None,
				version: Expr::Literal(Literal::None),
				timeout: Expr::Literal(Literal::None),
				explain: None,
				tempfiles: false,
			};

			let value = stk.run(|stk| recalc_stmt.compute(stk, ctx, opt, None)).await?;

			let Value::Array(Array(values)) = value else {
				fail!("Aggregate recalculation select statement return an invalid result");
			};
			if values.len() != recalculations.len() {
				fail!("Aggregate recalculation select statement return an invalid result");
			}

			for (idx, v) in values.into_iter().enumerate() {
				match &mut meta.aggregation_stats[recalculations[idx].stat] {
					AggregationStat::TimeMin {
						min: stat,
						..
					}
					| AggregationStat::TimeMax {
						max: stat,
						..
					} => {
						let Value::Datetime(d) = v else {
							fail!("Got wrong recalculation value")
						};
						*stat = d;
					}

					AggregationStat::NumberMin {
						min: stat,
						..
					}
					| AggregationStat::NumberMax {
						max: stat,
						..
					} => {
						let Value::Number(n) = v else {
							fail!("Got wrong recalculation value")
						};
						*stat = n;
					}

					_ => unreachable!(),
				}
			}
		}

		let doc =
			Value::Object(aggregation::create_field_document(&group, &meta.aggregation_stats))
				.into();

		let mut data = Value::empty_object();

		match &aggr.fields {
			AggregateFields::Value(_) => {
				fail!("Value selectors are not supported on views");
			}
			AggregateFields::Fields(items) => {
				for (name, expr) in items {
					let res = stk
						.run(|stk| expr.compute(stk, ctx, opt, Some(&doc)))
						.await
						.catch_return()?;
					data.set(stk, ctx, opt, name.as_ref(), res).await?;
				}
			}
		};

		record.data = data;
		let record = Arc::new(record);

		tx.set_record(db.namespace_id, db.database_id, view_table_name, &key, Arc::clone(&record))
			.await?;

		let id = RecordId {
			table: view_table_name.clone(),
			key,
		};

		let ns = self.doc_ctx.ns();
		let db = self.doc_ctx.db();

		let tb = ctx
			.tx()
			.get_or_add_tb(Some(ctx), &ns.name, &db.name, view_table_name, opt.version)
			.await?;
		let parent = NsDbCtx {
			ns: Arc::clone(ns),
			db: Arc::clone(db),
		};
		let doc_ctx =
			DocumentContext::initialise(ctx, &parent, tb, view_table_name, opt.version, true)
				.await?;

		Self::run_triggers(
			stk,
			ctx,
			opt,
			doc_ctx,
			id.into(),
			Action::Update,
			Some(record_before.into()),
			Some(record),
		)
		.await?;
		Ok(())
	}



	async fn process_view_record_update(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		group: Vec<Value>,
		view_table_name: &TableName,
		aggr: &AggregationAnalysis,
	) -> Result<()> {
		let db = self.doc_ctx.db();

		let key = RecordIdKey::Array(Array(group.clone()));
		let tx = ctx.tx();

		let k = key::record::new(db.namespace_id, db.database_id, view_table_name, &key);



		let mut record = if let Some(bytes) = tx.get_raw(&k, None).await? {
			revision::from_slice::<Record>(&bytes)?
		} else {
			fail!("Deletion for a view but no record exists for that view")
		};
		let record_before = record.clone();

		let Some(meta) = record.metadata.as_mut() else {
			fail!("Record for a view table had no valid metadata")
		};

		let mut before_args = Vec::with_capacity(aggr.aggregate_arguments.len());
		for a in aggr.aggregate_arguments.iter() {
			before_args.push(a.compute(stk, ctx, opt, Some(&self.initial)).await.catch_return()?)
		}

		let mut after_args = Vec::with_capacity(aggr.aggregate_arguments.len());
		for a in aggr.aggregate_arguments.iter() {
			after_args.push(a.compute(stk, ctx, opt, Some(&self.current)).await.catch_return()?)
		}

		let mut recalculations = Vec::new();
		for (idx, a) in meta.aggregation_stats.iter_mut().enumerate() {
			match a {
				AggregationStat::Count {
					..
				} => {}
				AggregationStat::CountValue {
					arg,
					count,
				} => {
					if before_args[*arg].is_truthy() {
						*count -= 1;
					}
					if after_args[*arg].is_truthy() {
						*count += 1;
					}
				}
				AggregationStat::NumberMax {
					arg,
					max,
				} => {
					let Value::Number(ref after) = after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "math::max".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `number` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};

					let Value::Number(before) = &before_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					if *after >= *max {
						*max = *after
					} else if *before == *max {


						recalculations.push(Recalculation {
							function: "math::max".to_string(),
							stat: idx,
							arg: *arg,
						})
					}
				}
				AggregationStat::NumberMin {
					arg,
					min,
				} => {
					let Value::Number(ref after) = after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "math::min".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `number` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};
					let Value::Number(before) = &before_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					if *after <= *min {
						*min = *after
					} else if *before == *min {
						recalculations.push(Recalculation {
							function: "math::min".to_string(),
							stat: idx,
							arg: *arg,
						})
					}
				}
				AggregationStat::Sum {
					arg,
					sum,
				} => {
					let Value::Number(ref after) = after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "math::sum".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `number` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};

					let Value::Number(before) = &before_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*sum = *sum - *before;
					*sum = sum.try_add(*after)?;
				}

				AggregationStat::Mean {
					arg,
					sum,
					..
				} => {
					let Value::Number(ref after) = after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "math::mean".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `number` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};

					let Value::Number(before) = &before_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*sum = *sum - *before;
					*sum = sum.try_add(*after)?;
				}
				AggregationStat::TimeMax {
					arg,
					max,
				} => {
					let Value::Datetime(after) = &after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "time::max".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `datetime` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};

					let Value::Datetime(before) = &before_args[*arg] else {
						fail!("Old record wasn't a datetime but was created with a number");
					};

					if *after >= *max {
						*max = *after;
					} else if *before == *max {
						recalculations.push(Recalculation {
							function: "time::max".to_string(),
							stat: idx,
							arg: *arg,
						});
					}
				}
				AggregationStat::TimeMin {
					arg,
					min,
				} => {
					let Value::Datetime(after) = &after_args[*arg] else {
						bail!(Error::InvalidFunctionArguments {
							name: "time::min".to_string(),
							message: format!(
								"Argument 1 was the wrong type. Expected `datetime` but found `{}`",
								after_args[*arg].to_sql()
							),
						})
					};

					let Value::Datetime(before) = &before_args[*arg] else {
						fail!("Old record wasn't a datetime but was created with a number");
					};

					if *after <= *min {
						*min = *after;
					} else if *before == *min && *after != *min {
						recalculations.push(Recalculation {
							function: "time::min".to_string(),
							stat: idx,
							arg: *arg,
						});
					}
				}
				AggregationStat::Variance {
					arg,
					sum,
					sum_of_squares,
					..
				}
				| AggregationStat::StdDev {
					arg,
					sum,
					sum_of_squares,
					..
				} => {
					let Value::Number(before) = &before_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					let Value::Number(after) = &after_args[*arg] else {
						fail!("Old record wasn't a number but was created with a number");
					};

					*sum = *sum - *before;
					*sum_of_squares = *sum_of_squares - before.try_mul(*before)?;
					*sum = *sum + *after;
					*sum_of_squares = *sum_of_squares + after.try_mul(*after)?;
				}
				AggregationStat::Accumulate {
					..
				} => fail!("Accumulate aggregation is not supported in materialized views"),
			}
		}

		if !recalculations.is_empty() {

			let exprs = recalculations
				.iter()
				.map(|x| {
					Expr::FunctionCall(Box::new(FunctionCall {
						receiver: Function::Normal(x.function.clone()),
						arguments: vec![aggr.aggregate_arguments[x.arg].clone()],
					}))
				})
				.collect();


			let mut condition = None;
			for (idx, g) in aggr.group_expressions.iter().enumerate() {
				let expr = Expr::Binary {
					left: Box::new(g.clone()),
					op: BinaryOperator::Equal,
					right: Box::new(group[idx].clone().into_literal()),
				};
				if let Some(c) = condition {
					condition = Some(Expr::Binary {
						left: Box::new(c),
						op: BinaryOperator::And,
						right: Box::new(expr),
					})
				} else {
					condition = Some(expr)
				}
			}

			let table_name = self.id()?.table.clone();

			let recalc_stmt = SelectStatement {

				fields: Fields::Value(Box::new(Selector {
					expr: Expr::Literal(Literal::Array(exprs)),
					alias: None,
				})),

				only: true,
				what: vec![Expr::Table(table_name.clone())],

				cond: condition.map(Cond),

				group: Some(Groups(Vec::new())),
				omit: vec![],
				with: None,
				split: None,
				order: None,
				limit: None,
				start: None,
				fetch: None,
				version: Expr::Literal(Literal::None),
				timeout: Expr::Literal(Literal::None),
				explain: None,
				tempfiles: false,
			};

			let value = stk.run(|stk| recalc_stmt.compute(stk, ctx, opt, None)).await?;

			let Value::Array(Array(values)) = value else {
				fail!("Aggregate recalculation select statement return an invalid result");
			};
			if values.len() != recalculations.len() {
				fail!("Aggregate recalculation select statement return an invalid result");
			}

			for (idx, v) in values.into_iter().enumerate() {
				match &mut meta.aggregation_stats[recalculations[idx].stat] {
					AggregationStat::TimeMin {
						min: stat,
						..
					}
					| AggregationStat::TimeMax {
						max: stat,
						..
					} => {
						let Value::Datetime(d) = v else {
							fail!("Got wrong recalculation value")
						};
						*stat = d;
					}

					AggregationStat::NumberMin {
						min: stat,
						..
					}
					| AggregationStat::NumberMax {
						max: stat,
						..
					} => {
						let Value::Number(n) = v else {
							fail!("Got wrong recalculation value")
						};
						*stat = n;
					}

					_ => unreachable!(),
				}
			}
		}

		let doc =
			Value::Object(aggregation::create_field_document(&group, &meta.aggregation_stats))
				.into();

		let mut data = Value::empty_object();

		match &aggr.fields {
			AggregateFields::Value(_) => {
				fail!("Value selectors are not supported on views");
			}
			AggregateFields::Fields(items) => {
				for (name, expr) in items {
					let res = stk
						.run(|stk| expr.compute(stk, ctx, opt, Some(&doc)))
						.await
						.catch_return()?;
					data.set(stk, ctx, opt, name.as_ref(), res).await?;
				}
			}
		};

		record.data = data;
		let record = Arc::new(record);

		tx.set_record(db.namespace_id, db.database_id, view_table_name, &key, Arc::clone(&record))
			.await?;

		let id = RecordId {
			table: view_table_name.to_owned(),
			key,
		};

		let ns = self.doc_ctx.ns();
		let db = self.doc_ctx.db();

		let tb = ctx
			.tx()
			.get_or_add_tb(Some(ctx), &ns.name, &db.name, view_table_name, opt.version)
			.await?;
		let parent = NsDbCtx {
			ns: Arc::clone(ns),
			db: Arc::clone(db),
		};
		let doc_ctx =
			DocumentContext::initialise(ctx, &parent, tb, view_table_name, opt.version, true)
				.await?;

		Self::run_triggers(
			stk,
			ctx,
			opt,
			doc_ctx,
			Arc::new(id),
			Action::Update,
			Some(record_before.into()),
			Some(record),
		)
		.await?;
		Ok(())
	}


	#[allow(clippy::too_many_arguments)]
	pub(crate) async fn run_triggers(
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc_ctx: DocumentContext,
		id: Arc<RecordId>,
		action: Action,
		initial: Option<Arc<Record>>,
		current: Option<Arc<Record>>,
	) -> Result<()> {













		let mut document = Document {
			doc_ctx,
			r#gen: None,
			retry: false,
			extras: Extras::Normal,
			current: current
				.map(|x| CursorDoc::new(Some(Arc::clone(&id)), None, x))
				.unwrap_or_else(|| CursorDoc::new(None, None, Value::None)),
			initial: initial
				.map(|x| CursorDoc::new(Some(Arc::clone(&id)), None, x))
				.unwrap_or_else(|| CursorDoc::new(None, None, Value::None)),
			current_reduced: None,
			initial_reduced: None,
			record_strategy: RecordStrategy::KeysAndValues,
			input_data: None,
			mutated: false,
			modified: tokio::sync::OnceCell::new(),
			id: Some(id),
		};

		stk.run(|stk| document.store_index_data(stk, ctx, opt)).await?;
		stk.run(|stk| document.process_views(stk, ctx, opt, action)).await?;
		stk.run(|stk| document.process_table_lives(stk, ctx, opt, action)).await?;
		stk.run(|stk| document.process_events(stk, ctx, opt, action, None)).await?;
		document.process_changefeeds(ctx, opt).await?;

		Ok(())
	}
}
