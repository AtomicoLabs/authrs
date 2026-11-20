use authrs_store::{Database, Engine, SqlVal, StoreError, Tx, SCHEMA};
use bytes::BytesMut;
use postgres::types::{IsNull, ToSql, Type};
use postgres::{Client, Error, NoTls, Transaction};
use std::error::Error as StdError;

pub struct PgDb {
    jobs: std::sync::mpsc::Sender<Box<dyn FnOnce(&mut Client) + Send>>,
}

pub fn connect(url: &str) -> Result<Engine<PgDb>, StoreError> {
    let (jobs, incoming) = std::sync::mpsc::channel::<Box<dyn FnOnce(&mut Client) + Send>>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let url = url.to_string();
    std::thread::spawn(move || {
        let mut client = match Client::connect(&url, NoTls) {
            Ok(client) => client,
            Err(err) => {
                let _ = ready_tx.send(Err(map_err(err)));
                return;
            }
        };
        if let Err(err) = client.batch_execute(SCHEMA) {
            let _ = ready_tx.send(Err(map_err(err)));
            return;
        }
        let _ = ready_tx.send(Ok(()));
        while let Ok(job) = incoming.recv() {
            job(&mut client);
        }
    });
    ready_rx
        .recv().map_err(|err| StoreError::Other(err.to_string()))??;
    Ok(Engine::new(PgDb { jobs }))
}

impl Database for PgDb {
    fn with_tx<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut dyn Tx) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        self.jobs
            .send(Box::new(move |client| {
                let result = (|| {
                    let tx = client.transaction().map_err(map_err)?;
                    let mut adapter = PgTx { tx };
                    let result = f(&mut adapter);
                    match result {
                        Ok(value) => {
                            adapter.tx.commit().map_err(map_err)?;
                            Ok(value)
                        }
                        Err(err) => Err(err),
                    }
                })();
                let _ = done_tx.send(result);
            })).map_err(|err| StoreError::Other(err.to_string()))?;
        done_rx.recv().map_err(|err| StoreError::Other(err.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_closed_port() {
        let err = connect("postgres://127.0.0.1:1/none").err().expect("connect");
        let StoreError::Other(_) = err else {
            panic!("expected other, got {err:?}");
        };
    }
}

struct PgTx<'a> {
    tx: Transaction<'a>,
}

#[derive(Debug)]
struct Param(SqlVal);

impl ToSql for Param {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn StdError + Sync + Send>> {
        match &self.0 {
            SqlVal::Null => Ok(IsNull::Yes),
            SqlVal::Text(value) => value.to_sql(ty, out),
            SqlVal::Int(value) => value.to_sql(ty, out),
        }
    }

    fn accepts(ty: &Type) -> bool {
        matches!(
            *ty,
            Type::TEXT
                | Type::VARCHAR
                | Type::INT8
                | Type::INT4
                | Type::INT2
                | Type::BOOL
                | Type::UNKNOWN
        )
    }

    postgres::types::to_sql_checked!();
}

fn params(values: &[SqlVal]) -> Vec<Param> {
    values.iter().cloned().map(Param).collect()
}

fn map_err(err: Error) -> StoreError {
    if let Some(code) = err.code() {
        if code.code() == "23505" {
            return StoreError::Conflict;
        }
    }
    let text = err.to_string();
    if text.to_lowercase().contains("unique") {
        return StoreError::Conflict;
    }
    StoreError::Other(text)
}

fn cell(row: &postgres::Row, index: usize) -> SqlVal {
    if let Ok(value) = row.try_get::<_, Option<i64>>(index) {
        return match value {
            Some(value) => SqlVal::Int(value),
            None => SqlVal::Null,
        };
    }
    if let Ok(value) = row.try_get::<_, Option<i32>>(index) {
        return match value {
            Some(value) => SqlVal::Int(i64::from(value)),
            None => SqlVal::Null,
        };
    }
    if let Ok(value) = row.try_get::<_, Option<String>>(index) {
        return match value {
            Some(value) => SqlVal::Text(value),
            None => SqlVal::Null,
        };
    }
    SqlVal::Null
}

impl Tx for PgTx<'_> {
    fn exec(&mut self, sql: &str, values: &[SqlVal]) -> Result<u64, StoreError> {
        let owned = params(values);
        let refs: Vec<&(dyn ToSql + Sync)> = owned.iter().map(|item| item as _).collect();
        self.tx
            .execute(sql, &refs)
            .map(|count| count as u64)
            .map_err(map_err)
    }

    fn query(&mut self, sql: &str, values: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
        let owned = params(values);
        let refs: Vec<&(dyn ToSql + Sync)> = owned.iter().map(|item| item as _).collect();
        let rows = self.tx.query(sql, &refs).map_err(map_err)?;
        Ok(rows
            .iter()
            .map(|row| (0..row.len()).map(|index| cell(row, index)).collect())
            .collect())
    }
}
