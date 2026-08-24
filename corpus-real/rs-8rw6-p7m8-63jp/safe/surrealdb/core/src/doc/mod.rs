






pub(crate) use self::document::*;
pub use self::event::AsyncEventRecord;
pub(crate) use self::lives::DefaultBroker;

mod document;

mod create;
mod delete;
mod insert;
mod relate;
mod select;
mod update;
mod upsert;

mod alter;
mod changefeeds;
mod check;
pub(crate) mod compute;
mod edges;
mod event;
mod field;
mod index;
mod lives;
mod output;
mod purge;
mod reduce;
mod store;
mod table;



#[derive(Debug)]
pub enum IgnoreError {
	Ignore,
	Error(anyhow::Error),
}

impl From<anyhow::Error> for IgnoreError {
	fn from(value: anyhow::Error) -> Self {
		IgnoreError::Error(value)
	}
}


#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub(crate) enum Action {
	Create,
	Update,
	Delete,
}
