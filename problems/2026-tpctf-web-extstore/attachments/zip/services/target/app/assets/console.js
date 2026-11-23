// console client
async function upload(file) {
  const fd = new FormData();
  fd.append('theme', file);
  return fetch('/console?stage=upload', { method: 'POST', body: fd });
}
