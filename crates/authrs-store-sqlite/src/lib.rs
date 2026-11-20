use authrs_store::{Database, Engine, SqlVal, StoreError, Tx, SCHEMA};
use rusqlite::types::{ToSql, ToSqlOutput, Value, ValueRef};
use rusqlite::{Connection, Transaction};
use std::path::Path;

pub struct SqliteDb {
    conn: Connection,
}

pub fn open(path: &Path, key: &str) -> Result<Engine<SqliteDb>, StoreError> {
    if key.is_empty() {
        return Err(StoreError::Other("sqlite key is required".into()));
    }
    let conn = Connection::open(path).map_err(|err| StoreError::Other(err.to_string()))?;
    conn.pragma_update(None, "key", key).map_err(|_| StoreError::BadKey)?;
    if conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .is_err()
    {
        return Err(StoreError::BadKey);
    }
    conn.execute_batch(SCHEMA).map_err(|err| StoreError::Other(err.to_string()))?;
    let _ = conn.pragma_update(None, "foreign_keys", "ON");
    Ok(Engine::new(SqliteDb { conn }))
}

impl Database for SqliteDb {
    fn with_tx<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut dyn Tx) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let tx = self.conn.transaction().map_err(map_err)?;
        let mut adapter = SqliteTx { tx };
        let result = f(&mut adapter);
        match result {
            Ok(value) => {
                adapter.tx.commit().map_err(map_err)?;
                Ok(value)
            }
            Err(err) => Err(err),
        }
    }
}

struct SqliteTx<'a> {
    tx: Transaction<'a>,
}

struct Param<'a>(&'a SqlVal);

impl ToSql for Param<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self.0 {
            SqlVal::Null => Ok(ToSqlOutput::Owned(Value::Null)),
            SqlVal::Text(value) => Ok(ToSqlOutput::Borrowed(ValueRef::Text(value.as_bytes()))),
            SqlVal::Int(value) => Ok(ToSqlOutput::Owned(Value::Integer(*value))),
        }
    }
}

fn qmarks(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' && index + 1 < bytes.len() && bytes[index + 1].is_ascii_digit() {
            out.push('?');
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                out.push(bytes[index] as char);
                index += 1;
            }
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

fn map_err(err: rusqlite::Error) -> StoreError {
    let text = err.to_string();
    let lower = text.to_lowercase();
    if lower.contains("unique") {
        StoreError::Conflict
    } else if lower.contains("not a database") || lower.contains("file is not a database") {
        StoreError::BadKey
    } else {
        StoreError::Other(text)
    }
}

fn cell(row: &rusqlite::Row<'_>, index: usize) -> SqlVal {
    match row.get::<_, Value>(index).unwrap_or(Value::Null) {
        Value::Null => SqlVal::Null,
        Value::Integer(value) => SqlVal::Int(value),
        Value::Real(value) => SqlVal::Int(value as i64),
        Value::Text(value) => SqlVal::Text(value),
        Value::Blob(value) => SqlVal::Text(String::from_utf8_lossy(&value).into_owned()),
    }
}

impl Tx for SqliteTx<'_> {
    fn exec(&mut self, sql: &str, values: &[SqlVal]) -> Result<u64, StoreError> {
        let sql = qmarks(sql);
        let params: Vec<Param> = values.iter().map(Param).collect();
        let refs: Vec<&dyn ToSql> = params.iter().map(|item| item as _).collect();
        self.tx
            .execute(&sql, refs.as_slice())
            .map(|count| count as u64)
            .map_err(map_err)
    }

    fn query(&mut self, sql: &str, values: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
        let sql = qmarks(sql);
        let params: Vec<Param> = values.iter().map(Param).collect();
        let refs: Vec<&dyn ToSql> = params.iter().map(|item| item as _).collect();
        let mut stmt = self.tx.prepare(&sql).map_err(map_err)?;
        let mut rows = stmt.query(refs.as_slice()).map_err(map_err)?;
        let mut out = Vec::new();
        loop {
            let Some(row) = rows.next().map_err(map_err)? else {
                break;
            };
            let width = row.as_ref().column_count();
            out.push((0..width).map(|index| cell(row, index)).collect());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(message: &str) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(message.into()))
    }

    #[test]
    fn classifies_errors_and_cells() {
        assert!(matches!(map_err(failure("UNIQUE constraint failed")), StoreError::Conflict));
        assert!(matches!(map_err(failure("file is not a database")), StoreError::BadKey));
        assert!(matches!(map_err(failure("no such table")), StoreError::Other(_)));

        let conn = Connection::open_in_memory().unwrap();
        let _ = conn.pragma_update(None, "key", "test-key");
        conn.execute_batch("CREATE TABLE sample (n REAL, b BLOB, i INTEGER, s TEXT, z TEXT)").unwrap();
        conn.execute("INSERT INTO sample VALUES (1.5, X'6869', 3, 'a', NULL)", []).unwrap();
        conn.query_row("SELECT n, b, i, s, z FROM sample", [], |row| {
            assert!(matches!(cell(row, 0), SqlVal::Int(1)));
            assert!(matches!(cell(row, 1), SqlVal::Text(_)));
            assert!(matches!(cell(row, 2), SqlVal::Int(3)));
            assert!(matches!(cell(row, 3), SqlVal::Text(ref value) if value == "a"));
            assert!(matches!(cell(row, 4), SqlVal::Null));
            Ok(())
        })
        .unwrap();
        let rewritten = qmarks("SELECT $1, $2");
        assert_eq!(rewritten, "SELECT ?1, ?2");
    }
}
