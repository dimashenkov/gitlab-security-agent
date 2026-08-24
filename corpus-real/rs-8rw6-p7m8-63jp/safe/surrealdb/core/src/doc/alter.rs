use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use crate::catalog::{LATEST_EDGE_VARIANT, RecordType};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{Options, Statement};
use crate::doc::{Document, Extras};
use crate::err::Error;
use crate::expr::data::Data;
use crate::expr::paths::{ID, IN, OUT};
use crate::expr::{AssignOperator, FlowResultExt, Idiom, Part};
use crate::val::{RecordId, Value};

impl Document {









	pub(super) fn generate_record_id(&mut self) -> Result<()> {

		if let Some(tb) = &self.r#gen {


			let existing_id = self.current.doc.as_ref().pick(&ID);
			let id = if existing_id.is_some() {

				existing_id.generate(tb.clone(), false)?
			} else {

				match &self.input_data {

					Some(data) => match data.pick(ID.as_ref()) {
						Value::None => RecordId::random_for_table(tb.clone()),

						id => id.generate(tb.clone(), false)?,

					},

					None => RecordId::random_for_table(tb.clone()),
				}
			};

			ensure!(
				!id.key.is_range(),
				Error::IdInvalid {
					value: id.to_sql(),
				}
			);

			self.id = Some(Arc::new(id));
		}

		Ok(())
	}






	pub(super) fn clear_record_data(&mut self) {
		*self.current.doc = Default::default();
	}








	pub(super) fn default_record_data(&mut self) -> Result<()> {

		let rid = self.id()?;

		self.current.doc.to_mut().def(RecordId::clone(&rid));

		if let Extras::Relate(l, r, _) = &self.extras {

















			if self.current.doc.edge_variant() != Some(LATEST_EDGE_VARIANT) {
				self.current.doc.set_record_type(RecordType::Edge {
					variant: LATEST_EDGE_VARIANT,
				});
			}

			match (self.initial.doc.as_ref().pick(&IN), self.is_new()) {

				(Value::RecordId(id), false) if id == *l => {
					self.current.doc.to_mut().put(&IN, l.clone().into());
				}

				(_, true) => {
					self.current.doc.to_mut().put(&IN, l.clone().into());
				}

				(v, _) => {
					bail!(Error::InOverride {
						value: v.to_sql(),
					})
				}
			}

			match (self.initial.doc.as_ref().pick(&OUT), self.is_new()) {

				(Value::RecordId(id), false) if id == *r => {
					self.current.doc.to_mut().put(&OUT, r.clone().into());
				}

				(_, true) => {
					self.current.doc.to_mut().put(&OUT, r.clone().into());
				}

				(v, _) => {
					bail!(Error::OutOverride {
						value: v.to_sql(),
					})
				}
			}
		}






		if self.initial.doc.is_edge() {
			self.current.doc.to_mut().put(&IN, self.initial.doc.as_ref().pick(&IN));
			self.current.doc.to_mut().put(&OUT, self.initial.doc.as_ref().pick(&OUT));
		}

		Ok(())
	}








	pub(super) fn process_merge_data(&mut self) -> Result<()> {

		let rid = self.id()?;

		self.current.doc.to_mut().def(RecordId::clone(&rid));

		if let Extras::Insert(v) = &self.extras {
			self.current.doc.to_mut().merge(Value::clone(v))?;
		}

		if let Extras::Relate(_, _, Some(v)) = &self.extras {
			self.current.doc.to_mut().merge(Value::clone(v))?;
		}

		Ok(())
	}








	pub(super) async fn process_record_data(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		if let Some(v) = self.input_data.clone() {
			match v {
				ComputedData::Patch(data) => {
					self.current.doc.to_mut().patch(data.as_ref().clone())?
				}
				ComputedData::Merge(data) => {
					self.current.doc.to_mut().merge(data.as_ref().clone())?
				}
				ComputedData::Replace(data) => {
					self.current.doc.to_mut().replace(data.as_ref().clone())?
				}
				ComputedData::Content(data) => {
					self.current.doc.to_mut().replace(data.as_ref().clone())?
				}
				ComputedData::Unset(i) => {
					for i in i.iter() {
						self.current.doc.to_mut().cut(i);
					}
				}
				ComputedData::Set(x) => {








					apply_assignments(stk, ctx, opt, self.current.doc.to_mut(), &x).await?;
				}
			};






			self.current_reduced = None;
		};

		Ok(())
	}















	pub(super) async fn compute_input_data(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Option<&ComputedData>> {

		if self.input_data.is_some() {
			return Ok(self.input_data.as_ref());
		}

		if let Some(data) = stm.data() {

			let input_value: Option<Arc<Value>> = match &self.extras {
				Extras::Insert(value) => Some(Arc::clone(value)),
				Extras::Relate(_, _, Some(value)) => Some(Arc::clone(value)),
				_ => None,
			};

			let doc = self.reduce_current(stk, ctx, opt).await?;

			self.input_data = Some(match data {

				Data::UnsetExpression(data) => ComputedData::Unset(data.clone()),

				Data::PatchExpression(data) => ComputedData::Patch(Arc::new(
					data.compute(stk, ctx, opt, Some(doc)).await.catch_return()?,
				)),

				Data::MergeExpression(data) => ComputedData::Merge(Arc::new(
					data.compute(stk, ctx, opt, Some(doc)).await.catch_return()?,
				)),

				Data::ReplaceExpression(data) => ComputedData::Replace(Arc::new(
					data.compute(stk, ctx, opt, Some(doc)).await.catch_return()?,
				)),

				Data::ContentExpression(data) => ComputedData::Content(Arc::new(
					data.compute(stk, ctx, opt, Some(doc)).await.catch_return()?,
				)),

				x @ Data::SetExpression(data) | x @ Data::UpdateExpression(data) => {
					let ctx = if matches!(x, Data::UpdateExpression(_)) {

						let mut ctx = Context::new_child(ctx);

						if let Some(value) = input_value {
							ctx.add_value("input", value);
						}

						ctx.freeze()
					} else {
						Arc::clone(ctx)
					};

					let mut assignments = Vec::with_capacity(data.len());
					for x in data.iter() {
						assignments.push(ComputedAssignment {
							place: x.place.clone(),
							operator: x.operator.clone(),
							value: x
								.value
								.compute(stk, &ctx, opt, Some(doc))
								.await
								.catch_return()?,
						});
					}

					ComputedData::Set(assignments)
				}
				x => bail!("Unexpected data clause type: {x:?}"),
			});
		}

		Ok(self.input_data.as_ref())
	}













	pub(super) async fn compute_input_value(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<Option<Arc<Value>>> {

		if self.compute_input_data(stk, ctx, opt, stm).await?.is_none() {
			return Ok(None);
		}


		let data = self.input_data.as_ref().expect("just verified Some above");
		Ok(Some(data.materialize(stk, ctx, opt).await?))
	}






	pub(super) async fn materialize_input_value(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<Option<Arc<Value>>> {
		match self.input_data.as_ref() {
			Some(data) => Ok(Some(data.materialize(stk, ctx, opt).await?)),
			None => Ok(None),
		}
	}
}

















#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) enum ComputedData {
	Patch(Arc<Value>),
	Merge(Arc<Value>),
	Replace(Arc<Value>),
	Content(Arc<Value>),
	Unset(Vec<Idiom>),
	Set(Vec<ComputedAssignment>),
}

impl ComputedData {





	pub(super) fn is_patch(&self) -> bool {
		matches!(self, ComputedData::Patch(_))
	}






	pub(super) fn pick(&self, path: &[Part]) -> Value {
		match self {
			ComputedData::Patch(v) => v.pick(path),
			ComputedData::Merge(v) => v.pick(path),
			ComputedData::Replace(v) => v.pick(path),
			ComputedData::Content(v) => v.pick(path),
			ComputedData::Unset(_) => Value::None,
			ComputedData::Set(assignments) => {
				for a in assignments {
					if a.operator == AssignOperator::Assign && a.place.0.as_slice() == path {
						return a.value.clone();
					}
				}
				Value::None
			}
		}
	}







	pub(super) async fn materialize(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<Arc<Value>> {
		match self {
			ComputedData::Patch(v) => Ok(Arc::clone(v)),
			ComputedData::Merge(v) => Ok(Arc::clone(v)),
			ComputedData::Replace(v) => Ok(Arc::clone(v)),
			ComputedData::Content(v) => Ok(Arc::clone(v)),
			ComputedData::Unset(_) => Ok(Arc::new(Value::None)),
			ComputedData::Set(assignments) => {
				let mut input = Value::Object(Default::default());
				apply_assignments(stk, ctx, opt, &mut input, assignments).await?;
				Ok(Arc::new(input))
			}
		}
	}
}














#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct ComputedAssignment {
	pub place: Idiom,
	pub operator: AssignOperator,
	pub value: Value,
}















async fn apply_assignments(
	stk: &mut Stk,
	ctx: &FrozenContext,
	opt: &Options,
	doc: &mut Value,
	assignments: &[ComputedAssignment],
) -> Result<()> {
	for x in assignments {
		match &x.operator {
			AssignOperator::Assign => match &x.value {
				Value::None => doc.del(stk, ctx, opt, &x.place).await?,
				_ => doc.set(stk, ctx, opt, &x.place, x.value.clone()).await?,
			},
			AssignOperator::Add => doc.increment(stk, ctx, opt, &x.place, x.value.clone()).await?,
			AssignOperator::Subtract => {
				doc.decrement(stk, ctx, opt, &x.place, x.value.clone()).await?
			}
			AssignOperator::Extend => doc.extend(stk, ctx, opt, &x.place, x.value.clone()).await?,
		}
	}
	Ok(())
}
