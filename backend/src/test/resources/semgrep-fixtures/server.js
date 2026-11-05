const express = require('express');
const cors = require('cors');
const { exec, execFile } = require('child_process');
const app = express();
// codelens-expect: PERMISSIVE_CORS
app.use(cors());
app.use(cors({ origin: ['https://devert.in'] }));

app.get('/user', async (req, res) => {
  const id = req.query.id;
  // codelens-expect: SQL_INJECTION
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  // codelens-expect: SQL_INJECTION
  const more = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  const safe = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  const tpl = await db.query(`SELECT * FROM users`);
  const label = logger.run(`processing ${id}`);
  res.json({ rows, more, safe, tpl, label });
});

app.get('/ping', (req, res) => {
  // codelens-expect: COMMAND_INJECTION
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
  // codelens-expect: COMMAND_INJECTION
  exec(`nslookup ${req.query.host}`);
  execFile('ping', ['-c', '1', req.query.host]);
  exec('uptime');
});

function render(el, html, cb) {
  // codelens-expect: UNSAFE_HTML
  el.innerHTML = html;
  el.innerHTML = '';
  el.textContent = html;
  el.innerHTML = DOMPurify.sanitize(html);
  // codelens-expect: CODE_INJECTION
  const v = eval(html);
  // codelens-expect: CODE_INJECTION
  setTimeout('run(' + html + ')', 10);
  setTimeout(cb, 10);
  setTimeout(() => cb(), 10);
  return v;
}

function check(x) {
  // codelens-expect: NAN_COMPARISON
  if (x === NaN) return 0;
  if (Number.isNaN(x)) return 1;
  // codelens-expect: SWALLOWED_EXCEPTION
  try {
    risky();
  } catch (e) {}
  try {
    risky();
  } catch (e) {
    console.error(e);
    throw e;
  }
}

const agent = new https.Agent({
  // codelens-expect: TLS_VERIFY_DISABLED
  rejectUnauthorized: false,
});
