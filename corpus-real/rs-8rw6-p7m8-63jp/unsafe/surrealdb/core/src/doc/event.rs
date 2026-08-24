use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};
use reblessive::TreeStack;
use reblessive::tree::Stk;
use revision::revisioned;
use surrealdb_strand::Strand;
#[cfg(not(target_family = "wasm"))]
use tokio::spawn;

use crate::catalog::providers::{DatabaseProvider, NamespaceProvider};
use crate::catalog::{EventDefinition, Record};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{Options, Session};
use crate::doc::{Action, CursorDoc, Document, DocumentContext};
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::iam::{Auth, AuthLimit};
use crate::key::root::eq::EventQueue;
use crate::kvs::TransactionType::Write;
use crate::kvs::sequences::Sequences;
use crate::kvs::tasklease::LeaseHandler;
use crate::kvs::{
	Datastore, HlcTimeStamp, KVValue, Key, LockType, NORMAL_BATCH_SIZE, Transaction,
	TransactionFactory, TransactionType, Val, impl_kv_value_revisioned,
};
use crate::val::{RecordId, Value};

impl Document {





	pub(super) async fn process_table_events(
		&mut self,
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

		let opt = &opt.new_with_perms(false);

		if self.doc_ctx.ev()?.is_empty() {
			return Ok(());
		}

		let input = self.materialize_input_value(stk, ctx, opt).await?;

		self.process_events(stk, ctx, opt, action, input).await
	}

	pub(super) async fn process_events(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		action: Action,
		input: Option<Arc<Value>>,
	) -> Result<()> {

		if opt.import {
			return Ok(());
		}

		if !self.is_modified() {
			return Ok(());
		}

		let opt = &opt.new_with_perms(false);


		for ev in self.doc_ctx.ev()?.iter() {

			let opt = AuthLimit::try_from(&ev.auth_limit)?.limit_opt(opt);

			let evt = match action {
				Action::Create => Value::from("CREATE"),
				Action::Update => Value::from("UPDATE"),
				Action::Delete => Value::from("DELETE"),
			};

			let after = self.current.doc.as_arc();
			let before = self.initial.doc.as_arc();

			let doc = if action == Action::Delete {
				&mut self.initial
			} else {
				&mut self.current
			};

			let mut ctx = Context::new_child(ctx);
			ctx.add_value("after", after);
			ctx.add_value("before", before);
			ctx.add_value("event", evt.into());
			ctx.add_value("value", doc.doc.as_arc());
			ctx.add_value("input", input.clone().unwrap_or_default());

			let ctx = ctx.freeze();

			let val = stk
				.run(|stk| ev.when.compute(stk, &ctx, &opt, Some(doc)))
				.await
				.catch_return()
				.map_err(|e| anyhow::anyhow!("Error while processing event {}: {e}", ev.name))?;

			if val.is_truthy() {
				if ev.is_async() {
					Self::process_event_async(ctx, opt, ev, &self.doc_ctx, doc).await?;
				} else {
					Self::process_event_sync(stk, ctx, opt, None, ev, doc).await?;
				}
			}
		}

		Ok(())
	}

	async fn process_event_sync(
		stk: &mut Stk,
		ctx: FrozenContext,
		opt: Options,
		_lh: Option<&LeaseHandler>,
		ev: &EventDefinition,
		doc: &CursorDoc,
	) -> Result<()> {

		for v in ev.then.iter() {
			stk.run(|stk| v.compute(stk, &ctx, &opt, Some(doc)))
				.await
				.catch_return()
				.map_err(|e| anyhow::anyhow!("Error while processing event {}: {e}", ev.name))?;
		}

		Ok(())
	}

	async fn process_event_async(
		ctx: FrozenContext,
		opt: Options,
		ev: &EventDefinition,
		doc_ctx: &DocumentContext,
		cursor_doc: &mut CursorDoc,
	) -> Result<()> {
		let node_id = ctx.node_id();
		let ts = HlcTimeStamp::next();
		let db = doc_ctx.db();
		let tx = ctx.tx();



		let key = EventQueue::new(
			db.namespace_id,
			db.database_id,
			&ev.target_table,
			&ev.name,
			ts,
			node_id,
		);
		let event_record = AsyncEventRecord::new(&opt, &ctx, ev, cursor_doc)?;
		tx.put(&key, &event_record).await?;
		tx.trigger_async_event();
		Ok(())
	}
}


#[revisioned(revision = 1)]
#[derive(Clone, Debug)]
pub struct AsyncEventRecord {


	attempt: u16,

	event_depth: u16,

	rid: Option<Arc<RecordId>>,

	cursor_record: Arc<Record>,

	fields_computed: bool,

	ns: Arc<str>,

	db: Arc<str>,

	perms: bool,

	auth_enabled: bool,


	values: HashMap<Strand, Arc<Value>>,

	auth_with_limit: Arc<Auth>,

	event_definition: EventDefinition,
}

impl_kv_value_revisioned!(AsyncEventRecord);

impl AsyncEventRecord {

	fn new(
		opt: &Options,
		ctx: &FrozenContext,
		event_definition: &EventDefinition,
		cursor_doc: &CursorDoc,
	) -> Result<Self> {
		let (ns, db) = opt.arc_ns_db()?;

		if let Some(d) = opt.async_event_depth()
			&& d >= event_definition.max_depth()
		{
			bail!(Error::EvReachMaxDepth(event_definition.name.to_string(), d))
		}
		Ok(Self {
			attempt: 0,
			event_depth: opt.async_event_depth().map(|d| d + 1).unwrap_or(0),
			rid: cursor_doc.rid.clone(),
			cursor_record: cursor_doc.doc.clone().into_read_only(),
			fields_computed: cursor_doc.fields_computed,
			ns,
			db,
			perms: opt.perms,
			auth_enabled: ctx.auth_enabled(),
			values: ctx.collect_values(HashMap::new()),
			auth_with_limit: Arc::clone(&opt.auth),
			event_definition: event_definition.clone(),

		})
	}


	fn build_event_context(&self, ctx: &FrozenContext) -> FrozenContext {
		let mut ctx = Context::new_child(ctx);
		ctx.add_values(self.values.clone());
		ctx.auth_enabled = self.auth_enabled;
		ctx.freeze()
	}


	async fn build_event_options(
		&self,
		tx: &Transaction,
		parent_opts: &Options,
		eq: &EventQueue<'_>,
	) -> Result<Options> {

		let ns = tx.expect_ns_by_name(&self.ns).await?;
		if ns.namespace_id != eq.ns {
			bail!(Error::EvNamespaceMismatch(
				self.event_definition.name.to_string(),
				ns.name.to_string(),
			));
		}
		let db = tx.expect_db_by_name(&self.ns, &self.db).await?;
		if db.database_id != eq.db {
			bail!(Error::EvDatabaseMismatch(
				self.event_definition.name.to_string(),
				db.name.to_string(),
			));
		}
		let opt = parent_opts.clone();
		let opt = opt
			.with_perms(self.perms)
			.with_auth(Arc::clone(&self.auth_with_limit))
			.with_async_event_depth(self.event_depth)
			.with_ns(Some(Arc::clone(&self.ns)))
			.with_db(Some(Arc::clone(&self.db)));
		Ok(opt)
	}


	fn build_event_cursor_doc(&self) -> CursorDoc {
		CursorDoc {
			rid: self.rid.clone(),
			ir: None,
			doc: Arc::clone(&self.cursor_record).into(),
			fields_computed: self.fields_computed,
		}
	}



	pub async fn process_next_events_batch(
		ds: &Datastore,
		lh: Option<&LeaseHandler>,
	) -> Result<usize> {

		let res = {
			if let Some(lh) = lh.as_ref() {
				lh.try_maintain_lease().await?;
			}
			let tx = ds.transaction(TransactionType::Read, LockType::Optimistic).await?;
			let (beg, end) = EventQueue::range();

			let res = catch!(tx, tx.scan(beg..end, NORMAL_BATCH_SIZE, 0, None).await);
			tx.cancel().await?;
			res
		};
		let count = res.len();
		Self::process_events_batch(ds, res, lh).await?;
		Ok(count)
	}

	#[cfg(not(target_family = "wasm"))]
	async fn process_events_batch(
		ds: &Datastore,
		res: Vec<(Key, Val)>,
		lh: Option<&LeaseHandler>,
	) -> Result<()> {
		if res.is_empty() {
			return Ok(());
		}


		let concurrency: usize = num_cpus::get().max(4);

		let workers = res.len().min(concurrency);

		let mut join_handles = Vec::with_capacity(workers);

		let (sender, receiver) = async_channel::bounded::<AsyncEventContext>(workers);


		for _ in 0..workers {
			let receiver = receiver.clone();

			let jh = spawn(async move {

				let mut stack = TreeStack::new();
				while let Ok(event_context) = receiver.recv().await {
					stack
						.enter(|stk| stk.run(|stk| event_context.run_event_checked(stk)))
						.finish()
						.await;
				}
			});
			join_handles.push(jh);
		}


		for (k, v) in res {
			match AsyncEventContext::new(ds, lh.cloned(), k, v) {
				Ok(event_context) => {
					sender.send(event_context).await?;
				}
				Err(e) => {

					error!("Unexpected Error while processing event: {e}");
				}
			};
			if let Some(lh) = lh {
				lh.try_maintain_lease().await?;
			}
		}
		sender.close();


		for jh in join_handles {
			if let Err(e) = jh.await {
				error!("Error while processing an event: {e}");
			}
		}
		Ok(())
	}

	#[cfg(target_family = "wasm")]
	async fn process_events_batch(
		ds: &Datastore,
		res: Vec<(Key, Val)>,
		lh: Option<&LeaseHandler>,
	) -> Result<()> {
		let mut stack = TreeStack::new();
		for (k, v) in res {
			if let Some(lh) = lh {
				lh.try_maintain_lease().await?;
			}
			let event_context = AsyncEventContext::new(ds, lh.cloned(), k, v)?;
			stack.enter(|stk| stk.run(|stk| event_context.run_event_checked(stk))).finish().await;
		}
		Ok(())
	}
}

struct AsyncEventContext {
	ctx: Option<Context>,
	opt: Options,
	tf: TransactionFactory,
	sequences: Sequences,
	lh: Option<LeaseHandler>,
	k: Key,
	v: Option<Val>,
}

impl AsyncEventContext {
	fn new(ds: &Datastore, lh: Option<LeaseHandler>, k: Key, v: Val) -> Result<Self> {
		Ok(Self {
			ctx: Some(ds.setup_ctx()?),
			opt: ds.setup_options(&Session::default()),
			tf: ds.transaction_factory().clone(),
			sequences: ds.sequences().clone(),
			lh,
			k,
			v: Some(v),
		})
	}

	async fn run_event_checked(mut self, stk: &mut Stk) {
		if let Some(ctx) = self.ctx.take()
			&& let Some(v) = self.v.take()
			&& let Err(e) = self.run_event(stk, ctx, v).await
		{
			error!("Unexpected error while processing an event. Error: {e} - Key: {:?}", self.k);
		}
	}

	async fn new_write_tx(&self) -> Result<Transaction> {
		self.tf.transaction(Write, LockType::Optimistic, self.sequences.clone()).await
	}

	async fn run_event(&mut self, stk: &mut Stk, mut ctx: Context, v: Val) -> Result<()> {
		let tx = self.new_write_tx().await?;
		ctx.set_transaction(Arc::new(tx));
		let ctx = ctx.freeze();
		let tx = ctx.tx();
		let eq = EventQueue::decode_key(&self.k)?;
		let mut ev = AsyncEventRecord::kv_decode_value(&v, ())?;
		match Self::process_event(stk, &ctx, &self.opt, self.lh.as_ref(), &eq, &ev).await {
			Ok(_) => {

				catch!(tx, tx.del(&eq).await);
				if let Err(e) = tx.commit().await {

					tx.cancel().await?;
					let tx = self.new_write_tx().await?;
					return Self::retry_attempt(tx, e, &eq, &mut ev).await;
				}
				Ok(())
			}
			Err(e) => {


				tx.cancel().await?;
				if let Some(final_error) = Self::is_final_error(&e).await? {
					let tx = self.new_write_tx().await?;
					return Self::final_error(tx, &eq, final_error).await;
				}
				let tx = self.new_write_tx().await?;
				Self::retry_attempt(tx, e, &eq, &mut ev).await
			}
		}
	}


	async fn retry_attempt(
		tx: Transaction,
		e: anyhow::Error,
		eq: &EventQueue<'_>,
		ev: &mut AsyncEventRecord,
	) -> Result<()> {


		ev.attempt += 1;
		if ev.attempt <= ev.event_definition.retry() {


			catch!(tx, tx.set(eq, ev).await);
		} else {
			warn!(
				"Final error after processing the event `{}` on table {} {} times: {e}",
				eq.ev, ev.event_definition.target_table, ev.attempt
			);
			catch!(tx, tx.del(eq).await);
		}
		catch!(tx, tx.commit().await);
		Ok(())
	}

	async fn is_final_error(e: &anyhow::Error) -> Result<Option<&Error>> {

		let se: Option<&Error> = e.downcast_ref();
		if matches!(
			se,
			Some(Error::EvNamespaceMismatch(..))
				| Some(Error::EvDatabaseMismatch(..))
				| Some(Error::EvReachMaxDepth(..))
		) {
			Ok(se)
		} else {
			Ok(None)
		}
	}

	async fn final_error(tx: Transaction, eq: &EventQueue<'_>, e: &Error) -> Result<()> {

		warn!("Event processing failed: {:?}", e);
		catch!(tx, tx.del(eq).await);
		catch!(tx, tx.commit().await);

		Ok(())
	}


	async fn process_event(
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		lh: Option<&LeaseHandler>,
		eq: &EventQueue<'_>,
		ev: &AsyncEventRecord,
	) -> Result<()> {
		let ctx = ev.build_event_context(ctx);
		let opt = ev.build_event_options(&ctx.tx(), opt, eq).await?;
		let doc = ev.build_event_cursor_doc();
		Document::process_event_sync(stk, ctx, opt, lh, &ev.event_definition, &doc).await
	}
}
