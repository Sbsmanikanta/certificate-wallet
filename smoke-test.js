const assert = require("assert");

const baseUrl = process.env.BASE_URL || "http://localhost:3000";

function getCookieHeader(setCookieHeader) {
  if (!setCookieHeader) {
    return "";
  }

  const entries = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  return entries.map((value) => value.split(";")[0]).join("; ");
}

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  return { response, payload };
}

async function main() {
  const health = await request("/api/health");
  assert.equal(health.response.status, 200, "Health endpoint should respond with 200.");

  const email = `smoke-${Date.now()}@example.com`;
  const password = "secret123";

  const signup = await request("/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Smoke Test", email, password })
  });

  assert.equal(signup.response.status, 201, "Signup should create a new user.");

  const cookie = getCookieHeader(signup.response.headers.get("set-cookie"));
  assert.ok(cookie.includes("sid="), "Signup should return a session cookie.");

  const create = await request("/api/documents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie
    },
    body: JSON.stringify({
      title: "Smoke Resume",
      documentType: "Resume",
      fileName: "resume.pdf",
      fileSize: 1024,
      fileType: "application/pdf",
      fileDataUrl: "data:application/pdf;base64,QQ=="
    })
  });

  assert.equal(create.response.status, 201, "Document upload should succeed.");
  assert.ok(create.payload.document?.id, "Created document should include an id.");

  const documentId = create.payload.document.id;

  const patch = await request(`/api/documents/${documentId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie
    },
    body: JSON.stringify({
      title: "Smoke Resume Updated",
      documentType: "Resume"
    })
  });

  assert.equal(patch.response.status, 200, "Document update should succeed.");
  assert.equal(patch.payload.document?.title, "Smoke Resume Updated", "Document title should update.");

  const list = await request("/api/documents?type=Resume&sort=title-asc", {
    headers: {
      Cookie: cookie
    }
  });

  assert.equal(list.response.status, 200, "Document list should succeed.");
  assert.ok(Array.isArray(list.payload.documents), "Document list should return an array.");
  assert.ok(list.payload.documents.some((item) => item.id === documentId), "Updated document should appear in list.");

  console.log("Smoke test passed.");
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
