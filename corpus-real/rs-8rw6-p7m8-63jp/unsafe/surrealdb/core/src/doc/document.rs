use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::OnceCell;

use crate::catalog::providers::TableProvider;
use crate::catalog::{
	DatabaseDefinition, EventDefinition, FieldDefinition, IndexDefinition, NamespaceDefinition,
	Record, SubscriptionDefinition, TableDefinition,
};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{Operable, Processable};
use crate::doc::alter::ComputedData;
use crate::idx::planner::RecordStrategy;
use crate::idx::planner::iterators::IteratorRecord;
use crate::val::{RecordId, TableName, Value};

pub(crate) struct Document {

	pub(super) doc_ctx: DocumentContext,

	pub(super) id: Option<Arc<RecordId>>,

	pub(super) r#gen: Option<TableName>,

	pub(super) retry: bool,

	pub(super) extras: Extras,

	pub(super) initial: CursorDoc,

	pub(super) current: CursorDoc,

	pub(super) initial_reduced: Option<CursorDoc>,

	pub(super) current_reduced: Option<CursorDoc>,

	pub(super) record_strategy: RecordStrategy,

	pub(super) input_data: Option<ComputedData>,











	pub(crate) mutated: bool,





	pub(super) modified: OnceCell<bool>,
}



#[derive(Debug)]
pub(super) enum Extras {

	Normal,






	Insert(Arc<Value>),









	Relate(RecordId, RecordId, Option<Arc<Value>>),
}







#[derive(Clone, Debug)]
pub(crate) struct NsDbCtx {
	pub(crate) ns: Arc<NamespaceDefinition>,
	pub(crate) db: Arc<DatabaseDefinition>,
}













#[derive(Clone, Debug)]
pub(crate) struct NsDbTbCtx {
	pub(crate) ns: Arc<NamespaceDefinition>,
	pub(crate) db: Arc<DatabaseDefinition>,
	pub(crate) tb: Arc<TableDefinition>,
	pub(crate) fields: Arc<[FieldDefinition]>,
}

impl NsDbTbCtx {




	pub(crate) async fn load(
		ctx: &FrozenContext,
		parent: &NsDbCtx,
		tb: Arc<TableDefinition>,
		table: &TableName,
		version: Option<u64>,
	) -> Result<Self> {
		use crate::kvs::cache;

		let txn = ctx.tx();

		let ns = parent.ns.namespace_id;

		let db = parent.db.database_id;

		let cache = match version {
			None => ctx.get_cache(),
			Some(_) => None,
		};

		if let Some(cache) = cache {

			let fields = {
				let key = cache::ds::Lookup::Fds(ns, db, table, tb.cache_fields_ts);
				match cache.get(&key) {
					Some(val) => val.try_into_fds()?,
					None => {
						let val = txn.all_tb_fields(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Fds(Arc::clone(&val)));
						val
					}
				}
			};

			Ok(Self {
				ns: Arc::clone(&parent.ns),
				db: Arc::clone(&parent.db),
				tb,
				fields,
			})
		} else {

			let fields = txn.all_tb_fields(ns, db, table, version).await?;

			Ok(Self {
				ns: Arc::clone(&parent.ns),
				db: Arc::clone(&parent.db),
				tb,
				fields,
			})
		}
	}
}







#[derive(Clone, Debug)]
pub(crate) struct NsDbTbMutCtx {
	pub(crate) ns: Arc<NamespaceDefinition>,
	pub(crate) db: Arc<DatabaseDefinition>,
	pub(crate) tb: Arc<TableDefinition>,
	pub(crate) fields: Arc<[FieldDefinition]>,
	pub(crate) events: Arc<[EventDefinition]>,
	pub(crate) tables: Arc<[TableDefinition]>,
	pub(crate) indexes: Arc<[IndexDefinition]>,
	pub(crate) lives: Arc<[SubscriptionDefinition]>,
}

impl NsDbTbMutCtx {






	pub(crate) async fn load(
		ctx: &FrozenContext,
		parent: &NsDbCtx,
		tb: Arc<TableDefinition>,
		table: &TableName,
		version: Option<u64>,
	) -> Result<Self> {
		use crate::kvs::cache;

		let txn = ctx.tx();

		let ns = parent.ns.namespace_id;

		let db = parent.db.database_id;

		let cache = match version {
			None => ctx.get_cache(),
			Some(_) => None,
		};

		if let Some(cache) = cache {

			let fields = async || -> Result<_> {
				let key = cache::ds::Lookup::Fds(ns, db, table, tb.cache_fields_ts);
				match cache.get(&key) {
					Some(val) => Ok(val.try_into_fds()?),
					None => {
						let val = txn.all_tb_fields(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Fds(Arc::clone(&val)));
						Ok(val)
					}
				}
			};

			let events = async || -> Result<_> {
				let key = cache::ds::Lookup::Evs(ns, db, table, tb.cache_events_ts);
				match cache.get(&key) {
					Some(val) => Ok(val.try_into_evs()?),
					None => {
						let val = txn.all_tb_events(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Evs(Arc::clone(&val)));
						Ok(val)
					}
				}
			};

			let tables = async || -> Result<_> {
				let key = cache::ds::Lookup::Fts(ns, db, table, tb.cache_tables_ts);
				match cache.get(&key) {
					Some(val) => Ok(val.try_into_fts()?),
					None => {
						let val = txn.all_tb_views(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Fts(Arc::clone(&val)));
						Ok(val)
					}
				}
			};

			let indexes = async || -> Result<_> {
				let key = cache::ds::Lookup::Ixs(ns, db, table, tb.cache_indexes_ts);
				match cache.get(&key) {
					Some(val) => Ok(val.try_into_ixs()?),
					None => {
						let val = txn.all_tb_indexes(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Ixs(Arc::clone(&val)));
						Ok(val)
					}
				}
			};

			let lives = async || -> Result<_> {
				let lvv = cache.get_live_queries_version(ns, db, table)?;
				let key = cache::ds::Lookup::Lvs(ns, db, table, lvv);
				match cache.get(&key) {
					Some(val) => Ok(val.try_into_lvs()?),
					None => {
						let val = txn.all_tb_lives(ns, db, table, None).await?;
						cache.insert(key, cache::ds::Entry::Lvs(Arc::clone(&val)));
						Ok(val)
					}
				}
			};

			let (fields, events, tables, indexes, lives) =
				futures::try_join!(fields(), events(), tables(), indexes(), lives())?;

			Ok(Self {
				ns: Arc::clone(&parent.ns),
				db: Arc::clone(&parent.db),
				tb,
				fields,
				events,
				tables,
				indexes,
				lives,
			})
		} else {

			let (fields, events, tables, indexes, lives) = futures::try_join!(
				txn.all_tb_fields(ns, db, table, version),
				txn.all_tb_events(ns, db, table, version),
				txn.all_tb_views(ns, db, table, version),
				txn.all_tb_indexes(ns, db, table, version),
				txn.all_tb_lives(ns, db, table, version),
			)?;

			Ok(Self {
				ns: Arc::clone(&parent.ns),
				db: Arc::clone(&parent.db),
				tb,
				fields,
				events,
				tables,
				indexes,
				lives,
			})
		}
	}
}
















#[derive(Clone, Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum DocumentContext {

	NsDbCtx(NsDbCtx),

	NsDbTbCtx(Arc<NsDbTbCtx>),

	NsDbTbMutCtx(Arc<NsDbTbMutCtx>),
}

impl DocumentContext {





	pub(crate) async fn initialise(
		ctx: &FrozenContext,
		parent: &NsDbCtx,
		tb: Arc<TableDefinition>,
		table: &TableName,
		version: Option<u64>,
		mutating: bool,
	) -> Result<Self> {
		if mutating {
			Ok(DocumentContext::NsDbTbMutCtx(Arc::new(

				NsDbTbMutCtx::load(ctx, parent, tb, table, version).await?,
			)))
		} else {
			Ok(DocumentContext::NsDbTbCtx(Arc::new(

				NsDbTbCtx::load(ctx, parent, tb, table, version).await?,
			)))
		}
	}


	pub(crate) fn ns(&self) -> &Arc<NamespaceDefinition> {
		match self {
			DocumentContext::NsDbCtx(ctx) => &ctx.ns,
			DocumentContext::NsDbTbCtx(ctx) => &ctx.ns,
			DocumentContext::NsDbTbMutCtx(ctx) => &ctx.ns,
		}
	}


	pub(crate) fn db(&self) -> &Arc<DatabaseDefinition> {
		match self {
			DocumentContext::NsDbCtx(ctx) => &ctx.db,
			DocumentContext::NsDbTbCtx(ctx) => &ctx.db,
			DocumentContext::NsDbTbMutCtx(ctx) => &ctx.db,
		}
	}


	pub(crate) fn tb(&self) -> Result<&Arc<TableDefinition>> {
		match self {
			DocumentContext::NsDbCtx(_) => Err(anyhow::anyhow!(
				"Table not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
			DocumentContext::NsDbTbCtx(ctx) => Ok(&ctx.tb),
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.tb),
		}
	}


	pub(crate) fn fd(&self) -> Result<&Arc<[FieldDefinition]>> {
		match self {
			DocumentContext::NsDbCtx(_) => Err(anyhow::anyhow!(
				"Fields not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
			DocumentContext::NsDbTbCtx(ctx) => Ok(&ctx.fields),
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.fields),
		}
	}




	pub(crate) fn ev(&self) -> Result<&Arc<[EventDefinition]>> {
		match self {
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.events),
			_ => Err(anyhow::anyhow!(
				"Events not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
		}
	}



	pub(crate) fn ft(&self) -> Result<&Arc<[TableDefinition]>> {
		match self {
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.tables),
			_ => Err(anyhow::anyhow!(
				"Foreign tables not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
		}
	}



	pub(crate) fn ix(&self) -> Result<&Arc<[IndexDefinition]>> {
		match self {
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.indexes),
			_ => Err(anyhow::anyhow!(
				"Indexes not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
		}
	}



	pub(crate) fn lv(&self) -> Result<&Arc<[SubscriptionDefinition]>> {
		match self {
			DocumentContext::NsDbTbMutCtx(ctx) => Ok(&ctx.lives),
			_ => Err(anyhow::anyhow!(
				"Live queries not defined in DocumentContext, this is certainly a bug and should be reported."
			)),
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct CursorDoc {
	pub(crate) rid: Option<Arc<RecordId>>,
	pub(crate) ir: Option<Arc<IteratorRecord>>,
	pub(crate) doc: CursorRecord,
	pub(crate) fields_computed: bool,
}

impl CursorDoc {


	pub(crate) fn with_parent_ctx<'a>(
		ctx: &'a FrozenContext,
		doc: Option<&CursorDoc>,
	) -> Cow<'a, FrozenContext> {
		if let Some(doc) = doc {
			let mut new_ctx = Context::new_child(ctx);
			new_ctx.add_value("parent", Arc::new(doc.doc.as_ref().clone()));
			Cow::Owned(new_ctx.freeze())
		} else {
			Cow::Borrowed(ctx)
		}
	}



	pub async fn update_parent<'a, F, R>(ctx: &'a FrozenContext, doc: Option<&CursorDoc>, f: F) -> R
	where
		F: AsyncFnOnce(Cow<'a, FrozenContext>) -> R,
	{
		let ctx = Self::with_parent_ctx(ctx, doc);
		f(ctx).await
	}
}






#[derive(Clone, Debug)]
pub(crate) struct CursorRecord {

	record: Arc<Record>,
}

impl CursorRecord {




	pub(crate) fn to_mut(&mut self) -> &mut Value {
		&mut Arc::make_mut(&mut self.record).data
	}




	pub(crate) fn as_arc(&self) -> Arc<Value> {
		Arc::new(self.record.data.clone())
	}


	pub(crate) fn into_read_only(self) -> Arc<Record> {
		self.record
	}


	pub(crate) fn as_ref(&self) -> &Value {
		&self.record.data
	}





	pub(crate) fn into_owned(self) -> Value {
		match Arc::try_unwrap(self.record) {
			Ok(record) => record.data,
			Err(arc) => arc.data.clone(),
		}
	}


	pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
		Arc::ptr_eq(&self.record, &other.record)
	}
}

impl Deref for CursorRecord {
	type Target = Record;
	fn deref(&self) -> &Self::Target {
		&self.record
	}
}

impl DerefMut for CursorRecord {
	fn deref_mut(&mut self) -> &mut Self::Target {
		Arc::make_mut(&mut self.record)
	}
}

impl CursorDoc {
	pub(crate) fn new<T: Into<CursorRecord>>(
		rid: Option<Arc<RecordId>>,
		ir: Option<Arc<IteratorRecord>>,
		doc: T,
	) -> Self {
		Self {
			rid,
			ir,
			doc: doc.into(),
			fields_computed: false,
		}
	}
}

impl From<Record> for CursorRecord {
	fn from(record: Record) -> Self {
		Self {
			record: Arc::new(record),
		}
	}
}

impl From<Arc<Record>> for CursorRecord {
	fn from(arc: Arc<Record>) -> Self {
		Self {
			record: arc,
		}
	}
}

impl From<Value> for CursorRecord {
	fn from(value: Value) -> Self {
		Self {
			record: Arc::new(Record::new(value)),
		}
	}
}

impl From<Value> for CursorDoc {
	fn from(val: Value) -> Self {
		Self {
			rid: None,
			ir: None,
			doc: val.into(),
			fields_computed: false,
		}
	}
}

impl Debug for Document {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "Document - id: <{:?}>", self.id)
	}
}

impl Document {

	pub fn new(pro: Processable) -> Self {

		let id = pro.rid;

		let ir = pro.ir;

		let (val, extras) = match pro.val {
			Operable::Value(v) => (v, Extras::Normal),
			Operable::Insert(v, o) => (v, Extras::Insert(o)),
			Operable::Relate(v, f, w, o) => (v, Extras::Relate(f, w, o)),
			_ => unreachable!(),
		};

		let initial = CursorDoc::new(id.clone(), ir, val);
		let current = initial.clone();

		Document {
			doc_ctx: pro.doc_ctx,
			id,
			r#gen: pro.generate,
			retry: false,
			extras,
			current,
			initial,
			current_reduced: None,
			initial_reduced: None,
			record_strategy: pro.record_strategy,
			input_data: None,
			mutated: false,
			modified: OnceCell::new(),
		}
	}


	#[inline]
	pub(super) fn is_new(&self) -> bool {
		self.initial.doc.as_ref().is_none()
	}
















	#[inline]
	pub(super) fn is_modified(&self) -> bool {
		if let Some(&v) = self.modified.get() {
			return v;
		}
		let v = if self.initial.doc.ptr_eq(&self.current.doc) {
			false
		} else {
			self.initial.doc.as_ref() != self.current.doc.as_ref()
		};
		let _ = self.modified.set(v);
		v
	}


	#[inline]
	pub(crate) fn is_key_only_iteration(&self) -> bool {
		matches!(self.record_strategy, RecordStrategy::Count | RecordStrategy::KeysOnly)
	}







	#[inline]
	pub(super) fn is_iteration_initial(&self) -> bool {
		!self.retry && self.initial.doc.as_ref().is_none()
	}































	#[inline]
	pub(super) fn is_specific_record_id(&self) -> bool {
		match self.extras {
			Extras::Insert(ref v) => !v.rid().is_nullish(),
			Extras::Normal => self.r#gen.is_none(),
			_ => false,
		}
	}


	pub fn modify_for_update_retry(&mut self, id: RecordId, record: Arc<Record>) {
		let retry = Arc::new(id);
		self.id = Some(Arc::clone(&retry));
		self.r#gen = None;
		self.retry = true;
		self.record_strategy = RecordStrategy::KeysAndValues;

		self.current = CursorDoc::new(Some(retry), None, record);
		self.initial = self.current.clone();

		self.input_data = None;
	}


	pub(crate) fn id(&self) -> Result<Arc<RecordId>> {
		match &self.id {
			Some(id) => Ok(Arc::clone(id)),
			_ => fail!("Expected a document id to be present"),
		}
	}


	pub fn inner_id(&self) -> Result<RecordId> {
		match self.id.clone() {
			Some(id) => Ok(Arc::unwrap_or_clone(id)),
			_ => fail!("Expected a document id to be present"),
		}
	}
}
