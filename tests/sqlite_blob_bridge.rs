//! Production Hermes/JSI SQLite bridge regressions for binary bindings.

use std::process::Command;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn eval(js: &str) -> String {
    let dir = tempfile::tempdir().expect("create eval tempdir");
    let entry = dir.path().join("eval.js");
    std::fs::write(
        &entry,
        format!(
            "(function () {{\n  var watchdog = setTimeout(function () {{\n    console.error('diagnostic eval timed out');\n    process.exitCode = 1;\n  }}, 55000);\n  var result = (\n{js}\n  );\n  function resolve(value) {{\n    clearTimeout(watchdog);\n    console.log(value);\n  }}\n  function reject(error) {{\n    clearTimeout(watchdog);\n    console.error(error && error.stack || error);\n    process.exitCode = 1;\n  }}\n  if (result && typeof result.then === 'function') result.then(resolve, reject);\n  else resolve(result);\n}})();\n"
        ),
    )
    .expect("write eval fixture");
    let output = Command::new(IBEX)
        .arg("capsec")
        .arg("audit")
        .arg(&entry)
        .output()
        .expect("run ibex");
    assert!(
        output.status.success(),
        "ibex failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .lines()
        .last()
        .unwrap_or("")
        .to_string()
}

#[test]
fn sqlite_bridge_round_trips_blob_without_number_array_expansion() {
    let result = eval(
        r#"(function () {
          var Database = require('exact:sqlite');
          var db = new Database(':memory:');
          db.exec('CREATE TABLE values_table (id INTEGER PRIMARY KEY, value TEXT)');
          var bytes = new Uint8Array(2 * 1024 * 1024);
          bytes[0] = 7; bytes[bytes.length - 1] = 249;
          db.query('INSERT INTO values_table (id, value) VALUES (?, ?)').run(1, bytes);
          var row = db.query(
            'SELECT value, typeof(value) AS kind, length(value) AS size FROM values_table'
          ).get();
          var ok = row.value instanceof Uint8Array &&
            row.value.length === bytes.length && row.value[0] === 7 &&
            row.value[row.value.length - 1] === 249 &&
            row.kind === 'blob' && row.size === bytes.length;
          db.close();
          return ok ? 'ok' : JSON.stringify(row);
        })()"#,
    );
    assert_eq!(result, "ok");
}

#[test]
fn legacy_text_declared_column_decodes_mixed_blob_rows_in_both_orders() {
    let result = eval(
        r#"(function () {
          var Database = require('exact:sqlite');
          function check(blobFirst) {
            var db = new Database(':memory:');
            db.exec('CREATE TABLE mixed (id INTEGER PRIMARY KEY, value TEXT)');
            var insert = db.query('INSERT INTO mixed (id, value) VALUES (?, ?)');
            var bytes = new Uint8Array([0, 1, 2, 254, 255]);
            insert.run(blobFirst ? 1 : 2, bytes);
            insert.run(blobFirst ? 2 : 1, 'legacy-text');
            var rows = db.query('SELECT value FROM mixed ORDER BY id').all();
            var binary = blobFirst ? rows[0].value : rows[1].value;
            var text = blobFirst ? rows[1].value : rows[0].value;
            var ok = binary instanceof Uint8Array && binary.length === 5 &&
              binary[3] === 254 && binary[4] === 255 && text === 'legacy-text';
            db.close();
            return ok;
          }
          return check(false) && check(true) ? 'ok' : 'bad';
        })()"#,
    );
    assert_eq!(result, "ok");
}
