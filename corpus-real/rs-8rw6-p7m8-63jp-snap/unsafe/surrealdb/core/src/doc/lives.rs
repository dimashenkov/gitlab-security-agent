use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use async_channel::Sender;
use chrono::Utc;
use futures::future::try_join_all;
use reblessive::TreeStack;
use reblessive::tree::Stk;
use tracing::instrument;

use super::IgnoreError;
use crate::catalog::{Permission, SubscriptionDefinition, SubscriptionFields};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{MessageBroker, Options, RoutedNotification};
use crate::doc::{Action, CursorDoc, Document};
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::expr::paths::{AC, ID, RD, TK};
use crate::kvs::Transaction;
use crate::types::{PublicAction, PublicNotification};
use crate::val::{Value, convert_value_to_public_value};

impl Document {





	pub(super) async fn process_table_lives(
		&mut self,
		_stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		action: Action,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}


		if ctx.broker().is_none() {

			return Ok(());
		};


		if !self.is_modified() {
			return Ok(());
		}


		let live_subscriptions = self.doc_ctx.lv()?;


		if live_subscriptions.is_empty() {
			return Ok(());
		}


		let (met, is_delete): (Arc<Value>, _) = match action {
			Action::Delete => (Value::from("DELETE").into(), true),
			Action::Create => (Value::from("CREATE").into(), false),
			Action::Update => (Value::from("UPDATE").into(), false),
		};



		let initial = self.initial.doc.as_arc();
		let current = self.current.doc.as_arc();


		let doc: &Self = &*self;

		let mut tasks = Vec::with_capacity(live_subscriptions.len());

		for live_subscription in live_subscriptions.iter() {




			let lqopt = opt.new_with_perms(true);
			let (met, current, initial) =
				(Arc::clone(&met), Arc::clone(&current), Arc::clone(&initial));
			tasks.push(async move {
				let mut stack = TreeStack::new();
				stack
					.enter(|stk| {
						doc.lq_compute(
							stk,
							ctx,
							live_subscription.clone(),
							lqopt,
							ctx.tx(),
							(met, initial, current),
							is_delete,
						)
					})
					.finish()
					.await
			});
		}

		try_join_all(tasks).await?;

		Ok(())
	}

















	#[allow(clippy::too_many_arguments, reason = "live-query dispatch shape")]
	async fn lq_compute(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		live_subscription: SubscriptionDefinition,
		opt: Options,
		tx: Arc<Transaction>,
		(met, initial, current): (Arc<Value>, Arc<Value>, Arc<Value>),
		is_delete: bool,
	) -> Result<()> {

		let sess = match live_subscription.session.as_ref() {
			Some(v) => v,
			None => return Ok(()),
		};








		if let Value::Object(ref session_obj) = *sess
			&& let Some(Value::Number(exp)) = session_obj.get("exp")
			&& Utc::now().timestamp() > (*exp).to_int()
		{
			return Ok(());
		}

		let auth = match live_subscription.auth.clone() {
			Some(v) => v,
			None => return Ok(()),
		};
		let opt = opt.with_auth(auth.into());

		let Some(sender) = ctx.broker() else {
			return Ok(());
		};


		let rid = self
			.id
			.clone()
			.ok_or_else(|| {
				Error::unreachable("Processing live query for record without a Record ID")
			})
			.map_err(anyhow::Error::new)?;





		let mut ctx = Context::background(ctx);



		ctx.set_transaction(tx);






		ctx.add_values(live_subscription.vars.clone());



		ctx.add_value("access", sess.pick(AC.as_ref()).into());
		ctx.add_value("auth", sess.pick(RD.as_ref()).into());
		ctx.add_value("token", sess.pick(TK.as_ref()).into());
		ctx.add_value("session", sess.clone().into());



		ctx.add_value("event", met);
		ctx.add_value("value", Arc::clone(&current));
		ctx.add_value("after", current);
		ctx.add_value("before", initial);

		let ctx = ctx.freeze();







		let source = if is_delete {
			&self.initial
		} else {
			&self.current
		};
		let Some(doc) = self.prepare_live_doc(stk, &ctx, &opt, source).await else {
			return Ok(());
		};




		match self.lq_check(stk, &ctx, &opt, &live_subscription, &doc).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					subscription_id = %live_subscription.id,
					error = %e,
					"LIVE notification skipped: WHERE clause evaluation failed",
				);
				return Ok(());
			}
			Ok(_) => (),
		}




		match self.lq_allow(stk, &ctx, &opt, is_delete).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					subscription_id = %live_subscription.id,
					error = %e,
					"LIVE notification skipped: table SELECT permission evaluation failed",
				);
				return Ok(());
			}
			Ok(_) => (),
		}
		if !sender.should_emit(*ctx.node_id().as_bytes(), *live_subscription.node.as_bytes())? {
			return Ok(());
		}



		let (action, mut result) = match live_subscription.fields {
			SubscriptionFields::Diff => {

				if is_delete {










					let operations = doc.doc.as_ref().diff(&Value::None);
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Delete, result)
				} else if self.is_new() {

					let operations = Value::None.diff(doc.doc.as_ref());
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Create, result)
				} else {








					let Some(previous) =
						self.prepare_live_doc(stk, &ctx, &opt, &self.initial).await
					else {
						return Ok(());
					};
					let operations = previous.doc.as_ref().diff(doc.doc.as_ref());
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Update, result)
				}
			}
			SubscriptionFields::Select(x) => {




				let result =
					match x.compute(stk, &ctx, &opt, Some(&doc)).await.map_err(IgnoreError::from) {
						Err(IgnoreError::Ignore) => return Ok(()),
						Err(IgnoreError::Error(e)) => {
							tracing::debug!(
								target: "surrealdb::core::doc::lives",
								subscription_id = %live_subscription.id,
								error = %e,
								"LIVE notification skipped: projection evaluation failed",
							);
							return Ok(());
						}
						Ok(x) => x,
					};
				let action = if is_delete {
					PublicAction::Delete
				} else if self.is_new() {
					PublicAction::Create
				} else {
					PublicAction::Update
				};
				(action, result)
			}
		};





		if let Some(fetchs) = live_subscription.fetch {
			let mut idioms = BTreeSet::new();
			for fetch in fetchs.iter() {
				if let Err(e) = fetch.compute(stk, &ctx, &opt, &mut idioms).await {
					tracing::debug!(
						target: "surrealdb::core::doc::lives",
						subscription_id = %live_subscription.id,
						error = %e,
						"LIVE notification skipped: FETCH expression evaluation failed",
					);
					return Ok(());
				}
			}
			for i in &idioms {
				if let Err(e) = stk.run(|stk| result.fetch(stk, &ctx, &opt, &i.0)).await {
					tracing::debug!(
						target: "surrealdb::core::doc::lives",
						subscription_id = %live_subscription.id,
						error = %e,
						"LIVE notification skipped: FETCH path resolution failed",
					);
					return Ok(());
				}
			}
		}


		let session_id = match sess.pick(ID.as_ref()) {
			Value::Uuid(uuid) => Some(uuid.into()),
			Value::String(s) => s.parse::<crate::val::Uuid>().ok().map(|uuid| uuid.into()),
			_ => None,
		};





		let rid_public = match convert_value_to_public_value(Value::RecordId(rid.as_ref().clone()))
		{
			Ok(v) => v,
			Err(e) => {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					subscription_id = %live_subscription.id,
					error = %e,
					"LIVE notification skipped: record id could not be converted to public value",
				);
				return Ok(());
			}
		};
		let result_public = match convert_value_to_public_value(result) {
			Ok(v) => v,
			Err(e) => {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					subscription_id = %live_subscription.id,
					error = %e,
					"LIVE notification skipped: result could not be converted to public value",
				);
				return Ok(());
			}
		};
		let notification = PublicNotification::new(
			live_subscription.id.into(),
			session_id,
			action,
			rid_public,
			result_public,
		);


		sender.send(RoutedNotification::new(live_subscription.node, notification)).await;

		Ok(())
	}









	#[instrument(level = "trace", target = "surrealdb::core::doc::lives", skip_all)]
	async fn prepare_live_doc(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		source: &CursorDoc,
	) -> Option<CursorDoc> {







		let mut doc = match self.reduce_to_owned(stk, ctx, opt, source).await {
			Ok(d) => d,
			Err(e) => {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					error = %e,
					"LIVE notification skipped: reduce_to_owned failed",
				);
				return None;
			}
		};
		if let Ok(rid) = self.id() {
			let fields = match self.doc_ctx.fd() {
				Ok(f) => f,
				Err(e) => {
					tracing::debug!(
						target: "surrealdb::core::doc::lives",
						error = %e,
						"LIVE notification skipped: field definitions unavailable",
					);
					return None;
				}
			};






			if let Err(e) =
				Document::computed_fields_inner(stk, ctx, opt, rid.as_ref(), fields, &mut doc, None)
					.await
			{
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					error = %e,
					"LIVE notification skipped: computed_fields_inner failed",
				);
				return None;
			}





			if let Err(e) = self.filter_computed_field_permissions(stk, ctx, opt, &mut doc).await {
				tracing::debug!(
					target: "surrealdb::core::doc::lives",
					error = %e,
					"LIVE notification skipped: computed-field permission filtering failed",
				);
				return None;
			}
		}
		Some(doc)
	}


	async fn lq_check(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		live_subscription: &SubscriptionDefinition,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {

		if let Some(cond) = live_subscription.cond.as_ref() {

			if !stk
				.run(|stk| cond.compute(stk, ctx, opt, Some(doc)))
				.await
				.catch_return()?
				.is_truthy()
			{

				return Err(IgnoreError::Ignore);
			}
		}

		Ok(())
	}

	async fn lq_allow(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		is_delete: bool,
	) -> Result<(), IgnoreError> {


		if ctx.check_perms(opt, crate::iam::Action::View)? {

			let tb = self.doc_ctx.tb()?;

			match &tb.permissions.select {
				Permission::None => return Err(IgnoreError::Ignore),
				Permission::Full => return Ok(()),
				Permission::Specific(e) => {

					let doc = if is_delete {
						&self.initial
					} else {
						&self.current
					};


					let opt = &opt.new_with_perms(false);

					if !stk
						.run(|stk| e.compute(stk, ctx, opt, Some(doc)))
						.await
						.catch_return()
						.is_ok_and(|x| x.is_truthy())
					{
						return Err(IgnoreError::Ignore);
					}
				}
			}
		}

		Ok(())
	}
}

#[derive(Clone, Debug)]
pub(crate) struct DefaultBroker {
	sender: Sender<RoutedNotification>,
	delivery: Arc<dyn MessageBroker>,
}

impl DefaultBroker {
	pub(crate) fn new(
		sender: Sender<RoutedNotification>,
		delivery: Arc<dyn MessageBroker>,
	) -> Arc<Self> {
		Arc::new(Self {
			sender,
			delivery,
		})
	}
}
impl MessageBroker for DefaultBroker {
	fn should_emit(&self, node_id: [u8; 16], target_node: [u8; 16]) -> Result<bool> {
		self.delivery.should_emit(node_id, target_node)
	}

	fn send(&self, item: RoutedNotification) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
		Box::pin(async move {


			let _ = self.sender.send(item).await;
		})
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use anyhow::Result;
	use chrono::Utc;

	use crate::catalog::providers::CatalogProvider;
	use crate::channel::Receiver;
	use crate::dbs::{Capabilities, Session};
	use crate::kvs::Datastore;
	use crate::kvs::LockType::Optimistic;
	use crate::kvs::TransactionType::Write;
	use crate::types::{
		PublicAction, PublicNotification, PublicRecordId, PublicRecordIdKey, PublicValue,
	};

	async fn new_ds_with_broker() -> Result<(Receiver<PublicNotification>, Datastore)> {
		let (send, recv) = crate::channel::bounded(1000);
		let ds = Datastore::builder()
			.with_capabilities(Capabilities::all())
			.with_auth(false)
			.with_notify(send)
			.build_with_path("memory")
			.await?;
		Ok((recv, ds))
	}

	async fn setup_ns_db_table(ds: &Datastore, ns: &str, db: &str, tb: &str) {
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();
		let ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(&format!("DEFINE TABLE {tb}"), &ses, None).await.unwrap();
	}

	fn record_user_session(ns: &str, db: &str, user_key: &str) -> Session {
		Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String(user_key.to_string()),
			}),
		)
		.with_rt(true)
	}








	#[tokio::test]
	async fn test_live_user_value_does_not_shadow_real_document() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(
			"LET $value = { ok: true }; LIVE SELECT * FROM person WHERE $value.ok = true",
			&ses,
			None,
		)
		.await
		.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:42 SET ok = false", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed");



		let result =
			tokio::time::timeout(tokio::time::Duration::from_millis(300), recv.recv()).await;
		assert!(
			result.is_err(),
			"no notification should fire when the real document does not match the WHERE",
		);
	}






	#[tokio::test]
	async fn test_live_expired_session_suppresses_notification() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let mut live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		live_ses.exp = Some(Utc::now().timestamp());
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		let res = ds.execute(&format!("CREATE {tb}"), &owner_ses, None).await.unwrap();
		assert!(res[0].result.is_ok(), "CREATE must succeed regardless of LIVE query TTL");

		let spurious =
			tokio::time::timeout(tokio::time::Duration::from_millis(200), recv.recv()).await;
		assert!(
			spurious.is_err(),
			"no notification must be sent after the LIVE query's session TTL has expired",
		);
	}



	#[tokio::test]
	async fn test_live_active_session_sends_notification() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(&format!("CREATE {tb}"), &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		assert_eq!(notif.action, PublicAction::Create);
	}







	#[tokio::test]
	async fn test_live_create_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', secret) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("CREATE person:1 SET secret = 'shh'", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		assert_eq!(notif.action, PublicAction::Create);
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("derived"),
			"CREATE notification must not include the restricted computed field; got: {obj:?}",
		);
	}





	#[tokio::test]
	async fn test_live_delete_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', secret) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();
		ds.execute("CREATE person:1 SET secret = 'shh'", &owner_ses, None).await.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("DELETE person:1", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		assert_eq!(notif.action, PublicAction::Delete);
		let PublicValue::Object(obj) = notif.result else {
			panic!("DELETE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("derived"),
			"DELETE notification must not include the restricted computed field; got: {obj:?}",
		);
	}






	#[tokio::test]
	async fn test_live_diff_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD name ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', name) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();



		ds.execute("CREATE person:1 SET name = 'foo'", &owner_ses, None).await.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT DIFF FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("UPDATE person:1 SET name = 'bar'", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Array(ops) = notif.result else {
			panic!("DIFF result should be a Value::Array, got: {:?}", notif.result);
		};
		for op in ops.iter() {
			let PublicValue::Object(obj) = op else {
				continue;
			};
			let path = obj.get("path");
			let targets_derived = path == Some(&PublicValue::String("/derived".to_string()));
			assert!(
				!targets_derived,
				"DIFF UPDATE must not reference the restricted computed field; ops: {ops:?}",
			);
		}
	}





	#[tokio::test]
	async fn test_live_conditional_permission_filters_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE doc PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD owner ON doc TYPE record<user>; \
			 DEFINE FIELD name ON doc TYPE string; \
			 DEFINE FIELD mine ON doc TYPE string \
			     COMPUTED string::concat('hi_', name) \
			     PERMISSIONS FOR select WHERE owner = $auth",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT * FROM doc", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}


		ds.execute("CREATE doc:1 SET owner = user:alice, name = 'one'", &owner_ses, None)
			.await
			.unwrap();
		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			obj.contains_key("mine"),
			"CREATE for own record must include the conditional computed field; got: {obj:?}",
		);


		ds.execute("CREATE doc:2 SET owner = user:bob, name = 'two'", &owner_ses, None)
			.await
			.unwrap();
		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("mine"),
			"CREATE for someone else's record must NOT include the conditional computed field; got: {obj:?}",
		);
	}








	#[tokio::test]
	async fn test_live_diff_does_not_leak_restricted_field_name() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD name ON person TYPE string; \
			 DEFINE FIELD secret ON person TYPE string PERMISSIONS FOR select WHERE false",
			&owner_ses,
			None,
		)
		.await
		.unwrap();


		ds.execute("CREATE person:50 SET name = 'foo', secret = 'shh'", &owner_ses, None)
			.await
			.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT DIFF FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("UPDATE person:50 SET name = 'bar'", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Array(ops) = notif.result else {
			panic!("DIFF result should be a Value::Array, got: {:?}", notif.result);
		};
		for op in ops.iter() {
			let PublicValue::Object(obj) = op else {
				continue;
			};
			let is_remove = obj.get("op") == Some(&PublicValue::String("remove".to_string()));
			let targets_secret =
				obj.get("path") == Some(&PublicValue::String("/secret".to_string()));
			assert!(
				!(is_remove && targets_secret),
				"DIFF UPDATE must not leak a Remove op for the restricted /secret field; ops: {ops:?}",
			);
		}
	}









	#[tokio::test]
	async fn test_live_diff_delete_does_not_leak_restricted_field_name() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD name ON person TYPE string; \
			 DEFINE FIELD secret ON person TYPE string PERMISSIONS FOR select WHERE false; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', name) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		ds.execute("CREATE person:51 SET name = 'foo', secret = 'shh'", &owner_ses, None)
			.await
			.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT DIFF FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("DELETE person:51", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		assert_eq!(notif.action, PublicAction::Delete);
		let PublicValue::Array(ops) = notif.result else {
			panic!("DIFF result should be a Value::Array, got: {:?}", notif.result);
		};
		for op in ops.iter() {
			let PublicValue::Object(obj) = op else {
				continue;
			};
			let path = obj.get("path");
			let targets_secret = path == Some(&PublicValue::String("/secret".to_string()));
			let targets_derived = path == Some(&PublicValue::String("/derived".to_string()));
			assert!(
				!targets_secret,
				"DIFF DELETE must not reference the restricted /secret field; ops: {ops:?}",
			);
			assert!(
				!targets_derived,
				"DIFF DELETE must not reference the restricted /derived computed field; ops: {ops:?}",
			);
		}
	}






	#[tokio::test]
	async fn test_live_where_doc_dependent_error_does_not_abort_create() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute("LIVE SELECT * FROM person WHERE string::len(name) > 3", &ses, None)
			.await
			.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:1", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed, not be aborted by LIVE WHERE error");

		let spurious =
			tokio::time::timeout(tokio::time::Duration::from_millis(200), recv.recv()).await;
		assert!(
			spurious.is_err(),
			"per-PR-214 design: WHERE errors silently skip the notification, no Action::Error",
		);
	}



	#[tokio::test]
	async fn test_live_projection_type_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute("LIVE SELECT string::len(NONE) FROM person", &ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:2", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0)
			.result
			.expect("CREATE should succeed, not be aborted by LIVE projection error");
	}




	#[tokio::test]
	async fn test_live_fetch_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute("LIVE SELECT * FROM person FETCH type::field(NONE)", &ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:12", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed despite invalid FETCH expression");
	}





	#[tokio::test]
	async fn test_live_field_permission_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person PERMISSIONS FOR select WHERE string::len(NONE)",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		let live_ses = record_user_session(ns, db, "alice");
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:20 SET secret = 'shh'", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0)
			.result
			.expect("CREATE should succeed despite erroring field SELECT permission");
	}




	#[tokio::test]
	async fn test_multiple_erroring_live_queries_do_not_abort_writes() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute("LIVE SELECT * FROM person WHERE string::len(name) > 3", &ses, None)
			.await
			.unwrap();
		ds.execute("LIVE SELECT * FROM person WHERE string::uppercase(name) = 'ALICE'", &ses, None)
			.await
			.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);

		let mut res =
			ds.execute("CREATE person:3", &ses_write, None).await.expect("execute should not Err");
		res.remove(0).result.expect("CREATE should succeed");

		let mut res = ds
			.execute("UPDATE person:3 SET name = 'Alice'", &ses_write, None)
			.await
			.expect("execute should not Err");
		res.remove(0).result.expect("UPDATE should succeed");

		let mut res =
			ds.execute("DELETE person:3", &ses_write, None).await.expect("execute should not Err");
		res.remove(0).result.expect("DELETE should succeed");
	}
}
