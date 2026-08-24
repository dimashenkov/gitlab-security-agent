use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use reblessive::tree::Stk;
use surrealdb_types::ToSql;

use crate::catalog::{self, FieldDefinition};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{Options, Statement};
use crate::doc::Document;
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::expr::data::Data;
use crate::expr::idiom::{Idiom, IdiomTrie, IdiomTrieContains};
use crate::expr::kind::{Kind, KindLiteral};
use crate::iam::{Action, AuthLimit};
use crate::val::value::CoerceError;
use crate::val::value::every::ArrayBehaviour;
use crate::val::{RecordId, Value};



fn clean_none(v: &mut Value) -> bool {
	match v {
		Value::None => false,
		Value::Object(o) => {
			o.retain(|_, v| clean_none(v));
			true
		}
		Value::Array(x) => {
			x.iter_mut().for_each(|x| {
				clean_none(x);
			});
			true
		}
		_ => true,
	}
}

impl Document {












	pub(super) fn cleanup_table_fields(&mut self) -> Result<()> {

		let tb = self.doc_ctx.tb()?;

		if tb.schemafull {




			let mut defined_field_names = IdiomTrie::new();


			let mut explicit_field_names = HashSet::new();
			for fd in self.doc_ctx.fd()?.iter() {
				explicit_field_names.insert(fd.name.clone());
			}


			fn kind_contains_object(kind: &Kind) -> bool {
				match kind {
					Kind::Object => true,
					Kind::Either(kinds) => kinds.iter().any(kind_contains_object),
					Kind::Array(inner, _) | Kind::Set(inner, _) => kind_contains_object(inner),
					Kind::Literal(KindLiteral::Object(_)) => true,
					Kind::Literal(KindLiteral::Array(x)) => x.iter().any(kind_contains_object),
					_ => false,
				}
			}


			for fd in self.doc_ctx.fd()?.iter() {

				let is_any = fd.field_kind.as_ref().is_some_and(Kind::is_any);

				let is_literal = fd.field_kind.as_ref().is_some_and(Kind::contains_literal);

				let contains_object = fd.field_kind.as_ref().is_some_and(kind_contains_object);





				let allows_nested = is_any || is_literal || (contains_object && fd.flexible);

				for k in self.current.doc.as_ref().each(&fd.name) {
					defined_field_names.insert(&k, allows_nested);




					for i in 1..k.len() {
						let ancestor = Idiom(k[..i].to_vec());
						if !explicit_field_names.contains(&ancestor) {


							defined_field_names.insert(&k[..i], true);
						}
					}
				}
			}


			for current_doc_field_idiom in
				self.current.doc.as_ref().every(None, true, ArrayBehaviour::Full).iter()
			{
				if current_doc_field_idiom.is_special() {

					continue;
				}


				match defined_field_names.contains(current_doc_field_idiom) {
					IdiomTrieContains::Exact(_) => {

						continue;
					}
					IdiomTrieContains::Ancestor(true) => {





						continue;
					}
					IdiomTrieContains::Ancestor(false) => {
						if let Some(part) = current_doc_field_idiom.last() {

							if part.is_index() {

								continue;
							}
						}



						ensure!(
							!tb.schemafull,

							Error::FieldUndefined {
								table: tb.name.as_str().to_string(),
								field: current_doc_field_idiom.clone(),
							}
						);


						self.current.doc.to_mut().cut(current_doc_field_idiom);
					}

					IdiomTrieContains::None => {


						ensure!(
							!tb.schemafull,

							Error::FieldUndefined {
								table: tb.name.as_str().to_string(),
								field: current_doc_field_idiom.clone(),
							}
						);


						self.current.doc.to_mut().cut(current_doc_field_idiom);
					}
				}
			}
		}



		clean_none(self.current.doc.to_mut());

		Ok(())
	}

















	pub(super) async fn process_table_fields(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}

		let rid = self.id()?;

		let inp = self.compute_input_value(stk, ctx, opt, stm).await?.unwrap_or_default();



		let mut skip: Option<&Idiom> = None;

		for fd in self.doc_ctx.fd()?.iter() {

			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);

			let skipped = match skip {


				Some(inner) => fd.name.starts_with(inner),
				None => false,
			};



			if !skipped {
				skip = None;
			}


			for (k, mut val) in self.current.doc.as_ref().walk(&fd.name) {

				let old = Arc::new(self.initial.doc.as_ref().pick(&k));

				let inp = Arc::new(inp.pick(&k));

				if fd.name.is_id() {
					ensure!(
						self.is_new() || val == *old,
						Error::FieldReadonly {
							field: fd.name.clone(),
							record: rid.to_sql(),
						}
					);

					if !self.is_new() {
						continue;
					}
				}








				if fd.readonly && !self.is_new() {
					if val.ne(&*old) {

						match stm.data() {



							Some(Data::ContentExpression(_)) if val.is_none() => {
								self.current
									.doc
									.to_mut()
									.set(stk, ctx, &opt, &k, old.as_ref().clone())
									.await?;
								continue;
							}



							_ => {
								bail!(Error::FieldReadonly {
									field: fd.name.clone(),
									record: rid.to_sql(),
								});
							}
						}
					}


					continue;
				}

				let mut field = FieldEditContext {
					context: None,
					doc: self,
					rid: Arc::clone(&rid),
					def: fd,
					stk,
					ctx,
					opt: &opt,
					old,
					user_input: inp,
				};

				if !skipped {

					if field.def.computed.is_some() {

						val = Value::None;
					} else {

						val = field.process_default_clause(val).await?;

						if field.def.value.is_some() {


							if val.is_none() {

								val = field.process_value_clause(val).await?;

								val = field.process_type_clause(val).await?;
							} else {

								val = field.process_type_clause(val).await?;

								val = field.process_value_clause(val).await?;

								val = field.process_type_clause(val).await?;
							}
						} else {

							val = field.process_type_clause(val).await?;
						}

						val = field.process_assert_clause(val).await?;
					}
				}

				val = field.process_permissions_clause(val).await?;

				if !skipped {

					if val.is_none() && fd.field_kind.as_ref().is_some_and(Kind::can_be_none) {
						skip = Some(&fd.name);
					}




					self.current.doc.to_mut().put(&k, val);
				}
			}
		}









		Ok(())
	}




	pub(super) async fn process_table_references(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}

		let rid = self.id()?;

		for fd in self.doc_ctx.fd()?.iter() {

			if fd.reference.is_none() {
				continue;
			}


			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);


			for (k, val) in self.current.doc.as_ref().walk(&fd.name) {

				let old = Arc::new(self.initial.doc.as_ref().pick(&k));

				let mut field = FieldEditContext {
					context: None,
					doc: self,
					rid: Arc::clone(&rid),
					def: fd,
					stk,
					ctx,
					opt: &opt,
					old,
					user_input: Value::None.into(),
				};

				field.process_reference_clause(&val).await?;
			}
		}

		Ok(())
	}





	pub(super) async fn cleanup_table_references(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}

		let rid = self.id()?;

		for fd in self.doc_ctx.fd()?.iter() {

			if fd.reference.is_none() {
				continue;
			}


			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);


			for (_, val) in self.current.doc.as_ref().walk(&fd.name) {

				if val.is_none() || val.is_empty_array() {
					continue;
				}


				let mut field = FieldEditContext {
					context: None,
					doc: self,
					rid: Arc::clone(&rid),
					def: fd,
					stk,
					ctx,
					opt: &opt,
					old: val.into(),
					user_input: Value::None.into(),
				};


				field.process_reference_clause(&Value::None).await?;
			}
		}

		Ok(())
	}
}

struct FieldEditContext<'a> {

	context: Option<Context>,

	def: &'a FieldDefinition,

	stk: &'a mut Stk,

	ctx: &'a FrozenContext,

	opt: &'a Options,

	doc: &'a Document,

	rid: Arc<RecordId>,

	old: Arc<Value>,

	user_input: Arc<Value>,
}

enum RefAction<'a> {
	Set(&'a RecordId),
	Delete(&'a RecordId),
}

impl FieldEditContext<'_> {

	async fn process_type_clause(&self, val: Value) -> Result<Value> {

		if let Some(kind) = &self.def.field_kind {

			if self.def.name.is_id() {

				if let Value::RecordId(ref id) = val {

					if !kind.is_record() {

						let inner = id.key.clone().into_value();


						inner.coerce_to_kind(kind).map_err(|e| Error::FieldCoerce {
							record: self.rid.to_sql(),
							field_name: self.def.name.to_sql(),
							error: Box::new(e),
						})?;
					}
				}

				else {

					bail!(Error::FieldCoerce {
						record: self.rid.to_sql(),
						field_name: "id".to_string(),
						error: Box::new(CoerceError::InvalidKind {
							from: val,
							into: "record".to_string(),
						}),
					});
				}
			}

			else {

				let val = val.coerce_to_kind(kind).map_err(|e| Error::FieldCoerce {
					record: self.rid.to_sql(),
					field_name: self.def.name.to_sql(),
					error: Box::new(e),
				})?;

				return Ok(val);
			}
		}

		Ok(val)
	}


	async fn process_default_clause(&mut self, val: Value) -> Result<Value> {

		if !val.is_none() {
			return Ok(val);
		}

		if !self.doc.is_new() && !matches!(self.def.default, catalog::DefineDefault::Always(_)) {
			return Ok(val);
		}

		let def = match &self.def.default {
			catalog::DefineDefault::Set(v) | catalog::DefineDefault::Always(v) => Some(v),
			_ => match &self.def.value {

				Some(v) if v.is_static() => Some(v),
				_ => None,
			},
		};

		if let Some(expr) = def {

			let now = Arc::new(val);

			let doc = Some(&self.doc.current);

			let ctx = match self.context.take() {
				Some(mut ctx) => {
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", now);
					ctx
				}
				None => {
					let mut ctx = Context::new_child(self.ctx);
					ctx.add_value("before", Arc::clone(&self.old));
					ctx.add_value("input", Arc::clone(&self.user_input));
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", now);
					ctx
				}
			};

			let ctx = ctx.freeze();

			let val =
				self.stk.run(|stk| expr.compute(stk, &ctx, self.opt, doc)).await.catch_return()?;

			self.context = Some(Context::unfreeze(ctx)?);

			return Ok(val);
		}

		Ok(val)
	}


	async fn process_value_clause(&mut self, val: Value) -> Result<Value> {

		if let Some(expr) = &self.def.value {

			let now = Arc::new(val);

			let doc = Some(&self.doc.current);

			let ctx = match self.context.take() {
				Some(mut ctx) => {
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", now);
					ctx
				}
				None => {
					let mut ctx = Context::new_child(self.ctx);
					ctx.add_value("before", Arc::clone(&self.old));
					ctx.add_value("input", Arc::clone(&self.user_input));
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", now);
					ctx
				}
			};

			let ctx = ctx.freeze();

			let val =
				self.stk.run(|stk| expr.compute(stk, &ctx, self.opt, doc)).await.catch_return()?;

			self.context = Some(Context::unfreeze(ctx)?);

			return Ok(val);
		}

		Ok(val)
	}


	async fn process_assert_clause(&mut self, val: Value) -> Result<Value> {



		if val.is_none() && self.def.field_kind.as_ref().is_some_and(Kind::can_be_none) {
			return Ok(val);
		}

		if let Some(expr) = &self.def.assert {

			let now = Arc::new(val.clone());

			let doc = Some(&self.doc.current);

			let ctx = match self.context.take() {
				Some(mut ctx) => {
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", Arc::clone(&now));
					ctx
				}
				None => {
					let mut ctx = Context::new_child(self.ctx);
					ctx.add_value("before", Arc::clone(&self.old));
					ctx.add_value("input", Arc::clone(&self.user_input));
					ctx.add_value("after", Arc::clone(&now));
					ctx.add_value("value", Arc::clone(&now));
					ctx
				}
			};

			let ctx = ctx.freeze();

			let res =
				self.stk.run(|stk| expr.compute(stk, &ctx, self.opt, doc)).await.catch_return()?;

			self.context = Some(Context::unfreeze(ctx)?);

			ensure!(
				res.is_truthy(),
				Error::FieldValue {
					record: self.rid.to_sql(),
					field: self.def.name.clone(),
					check: expr.to_sql(),
					value: now.to_sql(),
				}
			);
		}

		Ok(val)
	}


	async fn process_permissions_clause(&mut self, val: Value) -> Result<Value> {

		if self.ctx.check_perms(self.opt, Action::Edit)? {

			let perms = if self.doc.is_new() {
				&self.def.create_permission
			} else {
				&self.def.update_permission
			};

			let val = match perms {



				catalog::Permission::Full => val,



				catalog::Permission::None => {
					if val != *self.old {
						self.old.as_ref().clone()
					} else {
						val
					}
				}




				catalog::Permission::Specific(expr) => {

					let now = Arc::new(val.clone());

					let doc = Some(&self.doc.current);

					let opt = &self.opt.new_with_perms(false);


					let ctx = match self.context.take() {
						Some(mut ctx) => {
							ctx.add_value("after", Arc::clone(&now));
							ctx.add_value("value", now);
							ctx
						}
						None => {
							let mut ctx = Context::new_child(self.ctx);
							ctx.add_value("before", Arc::clone(&self.old));
							ctx.add_value("input", Arc::clone(&self.user_input));
							ctx.add_value("after", Arc::clone(&now));
							ctx.add_value("value", now);
							ctx
						}
					};

					let ctx = ctx.freeze();

					let res = self
						.stk
						.run(|stk| expr.compute(stk, &ctx, opt, doc))
						.await
						.catch_return()?;

					self.context = Some(Context::unfreeze(ctx)?);





					if res.is_truthy() || val == *self.old {
						val
					} else {
						self.old.as_ref().clone()
					}
				}
			};

			return Ok(val);
		}

		Ok(val)
	}


	async fn process_reference_clause(&mut self, val: &Value) -> Result<()> {

		if self.def.reference.is_some() {

			let old = self.old.as_ref();
			if old == val {

				return Ok(());
			}


			let mut actions = vec![];

			fn collect_rids(v: &Value) -> HashSet<&RecordId> {
				match v {
					Value::Array(arr) => {
						arr.iter().filter_map(|v| v.as_record()).collect::<HashSet<_>>()
					}
					Value::Set(set) => {
						set.iter().filter_map(|v| v.as_record()).collect::<HashSet<_>>()
					}
					Value::RecordId(rid) => HashSet::from([rid]),
					_ => HashSet::new(),
				}
			}

			let old = collect_rids(old);
			let new = collect_rids(val);

			for rid in old.difference(&new) {
				actions.push(RefAction::Delete(rid));
			}

			for rid in new.difference(&old) {
				actions.push(RefAction::Set(rid));
			}


			let ff = self.def.name.to_sql();
			for action in actions {
				match action {
					RefAction::Set(rid) => {
						let (ns, db) = self.ctx.expect_ns_db_ids(self.opt).await?;
						let key = crate::key::r#ref::new(
							ns,
							db,
							&rid.table,
							&rid.key,
							&self.rid.table,
							&ff,
							&self.rid.key,
						);

						self.ctx.tx().set(&key, &()).await?;
					}
					RefAction::Delete(rid) => {
						let (ns, db) = self.ctx.expect_ns_db_ids(self.opt).await?;
						let key = crate::key::r#ref::new(
							ns,
							db,
							&rid.table,
							&rid.key,
							&self.rid.table,
							&ff,
							&self.rid.key,
						);

						self.ctx.tx().del(&key).await?;
					}
				}
			}
		}
		Ok(())
	}
}
