function applyApiHeaders(res) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
}

function requirePost(req, res) {
  applyApiHeaders(res);
  if (req.method === "POST") return true;
  res.setHeader("Allow", "POST");
  res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  return false;
}

function failure(res, status, code, message) {
  return res.status(status).json({ ok: false, code, message });
}

module.exports = { applyApiHeaders, failure, requirePost };
