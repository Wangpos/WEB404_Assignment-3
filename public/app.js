// Front-end for the lab. Uses textContent everywhere so file names returned by
// the server are never interpreted as HTML.
async function refreshList(form, listEl) {
  const res = await fetch(form.dataset.list);
  const files = await res.json();
  listEl.replaceChildren();
  if (files.length === 0) {
    const li = document.createElement('li');
    li.textContent = '(empty)';
    listEl.append(li);
    return;
  }
  for (const f of files) {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = f.url;
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = f.originalName || f.name;
    li.append(a, document.createTextNode(` (${f.size} bytes${f.mime ? ', ' + f.mime : ''})`));
    listEl.append(li);
  }
}

function setup(formId, resultId, listId) {
  const form = document.getElementById(formId);
  const result = document.getElementById(resultId);
  const list = document.getElementById(listId);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    result.className = 'result';
    result.textContent = 'Uploading...';
    try {
      const res = await fetch(form.dataset.endpoint, { method: 'POST', body: data });
      const body = await res.json();
      result.classList.add(res.ok ? 'ok' : 'fail');
      result.textContent = `HTTP ${res.status}\n` + JSON.stringify(body, null, 2);
    } catch (err) {
      result.classList.add('fail');
      result.textContent = 'Request failed: ' + err.message;
    }
    refreshList(form, list);
  });

  refreshList(form, list);
}

setup('vuln-form', 'vuln-result', 'vuln-files');
setup('secure-form', 'secure-result', 'secure-files');
