const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, "data");
const STORE_PATH = path.join(DATA_DIR, "store.json");
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_SECONDS * 1000;
const MAX_JSON_BODY_BYTES = 6 * 1024 * 1024;
const MAX_DOCUMENT_FILE_SIZE = 2 * 1024 * 1024;
const MAX_NAME_LENGTH = 80;
const MAX_TITLE_LENGTH = 120;
const MAX_DOCUMENT_TYPE_LENGTH = 60;
const ALLOWED_FILE_TYPES = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/avif"
]);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const rateLimitStore = new Map();

const STATIC_CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
  ".avif": "image/avif"
};

const identityTypes = ["aadhaar card", "ration card", "pan card", "voter id", "passport", "driving license"];
const academicTypes = ["marksheet", "marklist", "certificate", "participation certificate", "resume"];

function applySecurityHeaders(headers = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...headers
  };
}

function getClientAddress(request) {
  const forwarded = request.headers["x-forwarded-for"];
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  return request.socket.remoteAddress || "unknown";
}

function isRateLimited(request, scope, limit, windowMs) {
  const key = `${scope}:${getClientAddress(request)}`;
  const now = Date.now();
  const current = rateLimitStore.get(key);

  if (!current || current.expiresAt <= now) {
    rateLimitStore.set(key, { count: 1, expiresAt: now + windowMs });
    return false;
  }

  if (current.count >= limit) {
    return true;
  }

  current.count += 1;
  return false;
}

function normalizeText(value) {
  return (value || "").toString().trim();
}

function isValidEmail(email) {
  return EMAIL_PATTERN.test(email);
}

function sanitizeStore(store) {
  const now = Date.now();
  const sessions = Array.isArray(store.sessions) ? store.sessions : [];
  const filteredSessions = sessions.filter((session) => {
    const createdAt = new Date(session.createdAt).getTime();
    return Number.isFinite(createdAt) && createdAt + SESSION_MAX_AGE_MS > now;
  });

  if (filteredSessions.length !== sessions.length) {
    store.sessions = filteredSessions;
    writeStore(store);
  }

  return store;
}

function validateDocumentPayload(body, { requireFileFields }) {
  const title = normalizeText(body.title);
  const documentType = normalizeText(body.documentType);
  const fileName = normalizeText(body.fileName);
  const fileType = normalizeText(body.fileType);
  const fileDataUrl = body.fileDataUrl || "";
  const fileSize = Number(body.fileSize) || 0;

  if (!title || !documentType) {
    return "Title and document type are required.";
  }

  if (title.length > MAX_TITLE_LENGTH) {
    return `Title must be ${MAX_TITLE_LENGTH} characters or fewer.`;
  }

  if (documentType.length > MAX_DOCUMENT_TYPE_LENGTH) {
    return `Document type must be ${MAX_DOCUMENT_TYPE_LENGTH} characters or fewer.`;
  }

  if (!requireFileFields) {
    return null;
  }

  if (!fileName || !fileType || !fileDataUrl) {
    return "fileName, fileType, and fileDataUrl are required.";
  }

  if (!ALLOWED_FILE_TYPES.has(fileType)) {
    return "Only PDF, PNG, JPG, WEBP, and AVIF files are supported.";
  }

  if (fileSize <= 0 || fileSize > MAX_DOCUMENT_FILE_SIZE) {
    return "Please upload a file smaller than 2 MB.";
  }

  if (typeof fileDataUrl !== "string" || !fileDataUrl.startsWith(`data:${fileType};base64,`)) {
    return "Invalid file data.";
  }

  return null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedValue) {
  if (!storedValue) {
    return false;
  }

  if (!storedValue.includes(":")) {
    return storedValue === password;
  }

  const [salt, storedHash] = storedValue.split(":");
  const computedHash = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(storedHash, "hex"), Buffer.from(computedHash, "hex"));
}

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(STORE_PATH)) {
    fs.writeFileSync(STORE_PATH, JSON.stringify({ users: [], documents: [], sessions: [] }, null, 2));
  }
}

function readStore() {
  ensureStore();
  return sanitizeStore(JSON.parse(fs.readFileSync(STORE_PATH, "utf8")));
}

function writeStore(store) {
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, applySecurityHeaders({
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  }));
  response.end(JSON.stringify(payload));
}

function sendNoContent(response, headers = {}) {
  response.writeHead(204, applySecurityHeaders(headers));
  response.end();
}

function sendText(response, statusCode, message) {
  response.writeHead(statusCode, applySecurityHeaders({ "Content-Type": "text/plain; charset=utf-8" }));
  response.end(message);
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_JSON_BODY_BYTES) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });

    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error("Invalid JSON body."));
      }
    });

    request.on("error", reject);
  });
}

function parseCookies(request) {
  const cookieHeader = request.headers.cookie || "";
  return cookieHeader.split(";").reduce((cookies, part) => {
    const [rawName, ...rest] = part.trim().split("=");
    if (!rawName) {
      return cookies;
    }

    cookies[rawName] = decodeURIComponent(rest.join("=") || "");
    return cookies;
  }, {});
}

function getSessionUser(request, store) {
  const cookies = parseCookies(request);
  const sessionId = cookies.sid;
  if (!sessionId) {
    return null;
  }

  const session = store.sessions.find((item) => item.id === sessionId);
  if (!session) {
    return null;
  }

  const createdAt = new Date(session.createdAt).getTime();
  if (!Number.isFinite(createdAt) || createdAt + SESSION_MAX_AGE_MS <= Date.now()) {
    store.sessions = store.sessions.filter((item) => item.id !== sessionId);
    writeStore(store);
    return null;
  }

  return store.users.find((user) => user.id === session.userId) || null;
}

function createSession(store, user) {
  const sessionId = crypto.randomUUID();
  store.sessions = store.sessions.filter((session) => session.userId !== user.id);
  store.sessions.push({
    id: sessionId,
    userId: user.id,
    createdAt: new Date().toISOString()
  });
  writeStore(store);
  return sessionId;
}

function clearSession(request, store) {
  const cookies = parseCookies(request);
  const sessionId = cookies.sid;
  if (!sessionId) {
    return;
  }

  store.sessions = store.sessions.filter((session) => session.id !== sessionId);
  writeStore(store);
}

function toSafeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

function createSessionCookie(sessionId) {
  return `sid=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_MAX_AGE_SECONDS}`;
}

function clearSessionCookie() {
  return "sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0";
}

function getUserDocuments(store, userId) {
  return store.documents.filter((document) => document.ownerId === userId);
}

function normalizeDocument(document) {
  return {
    id: document.id,
    ownerId: document.ownerId,
    title: document.title,
    documentType: document.documentType,
    fileName: document.fileName,
    fileSize: document.fileSize,
    fileType: document.fileType,
    fileDataUrl: document.fileDataUrl,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt || document.createdAt
  };
}

function sortDocuments(documents, sortKey) {
  const items = [...documents];

  if (sortKey === "oldest") {
    return items.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  }

  if (sortKey === "title-asc") {
    return items.sort((a, b) => a.title.localeCompare(b.title));
  }

  if (sortKey === "type-asc") {
    return items.sort((a, b) => a.documentType.localeCompare(b.documentType));
  }

  return items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function serveStaticFile(requestPath, response) {
  const safePath = requestPath === "/" ? "/login.html" : requestPath;
  const resolvedPath = path.normalize(path.join(ROOT_DIR, safePath));

  if (!resolvedPath.startsWith(ROOT_DIR)) {
    sendText(response, 403, "Forbidden");
    return;
  }

  fs.readFile(resolvedPath, (error, fileBuffer) => {
    if (error) {
      sendText(response, 404, "Not Found");
      return;
    }

    const extension = path.extname(resolvedPath).toLowerCase();
    response.writeHead(200, applySecurityHeaders({
      "Content-Type": STATIC_CONTENT_TYPES[extension] || "application/octet-stream"
    }));
    response.end(fileBuffer);
  });
}

async function handleApi(request, response, url) {
  const store = readStore();
  const user = getSessionUser(request, store);

  if (request.method === "GET" && url.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", timestamp: new Date().toISOString() });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/session") {
    if (!user) {
      sendJson(response, 401, { message: "Not authenticated." });
      return;
    }

    sendJson(response, 200, { user: toSafeUser(user) });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/signup") {
    if (isRateLimited(request, "signup", 8, 10 * 60 * 1000)) {
      sendJson(response, 429, { message: "Too many signup attempts. Please wait and try again." });
      return;
    }

    const body = await parseBody(request);
    const name = normalizeText(body.name);
    const email = normalizeText(body.email).toLowerCase();
    const password = body.password || "";

    if (!name || !email || !password) {
      sendJson(response, 400, { message: "Name, email, and password are required." });
      return;
    }

    if (name.length > MAX_NAME_LENGTH) {
      sendJson(response, 400, { message: `Name must be ${MAX_NAME_LENGTH} characters or fewer.` });
      return;
    }

    if (!isValidEmail(email)) {
      sendJson(response, 400, { message: "Please enter a valid email address." });
      return;
    }

    if (password.length < 6) {
      sendJson(response, 400, { message: "Password must be at least 6 characters." });
      return;
    }

    if (store.users.some((item) => item.email === email)) {
      sendJson(response, 409, { message: "An account with this email already exists." });
      return;
    }

    const newUser = {
      id: `USER-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      name,
      email,
      password: hashPassword(password),
      createdAt: new Date().toISOString()
    };

    store.users.push(newUser);
    const sessionId = createSession(store, newUser);

    sendJson(
      response,
      201,
      { user: toSafeUser(newUser) },
      { "Set-Cookie": createSessionCookie(sessionId) }
    );
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/login") {
    if (isRateLimited(request, "login", 12, 10 * 60 * 1000)) {
      sendJson(response, 429, { message: "Too many login attempts. Please wait and try again." });
      return;
    }

    const body = await parseBody(request);
    const email = normalizeText(body.email).toLowerCase();
    const password = body.password || "";

    if (!isValidEmail(email) || !password) {
      sendJson(response, 400, { message: "Valid email and password are required." });
      return;
    }

    const existingUser = store.users.find((item) => item.email === email && verifyPassword(password, item.password));
    if (!existingUser) {
      sendJson(response, 401, { message: "Invalid email or password." });
      return;
    }

    const sessionId = createSession(store, existingUser);
    sendJson(
      response,
      200,
      { user: toSafeUser(existingUser) },
      { "Set-Cookie": createSessionCookie(sessionId) }
    );
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    clearSession(request, store);
    sendNoContent(response, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  if (!user) {
    sendJson(response, 401, { message: "Please login to continue." });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/dashboard") {
    const documents = sortDocuments(getUserDocuments(store, user.id), "newest");

    sendJson(response, 200, {
      stats: {
        totalDocuments: documents.length,
        identityDocuments: documents.filter((document) => identityTypes.includes(document.documentType.toLowerCase())).length,
        academicDocuments: documents.filter((document) => academicTypes.includes(document.documentType.toLowerCase())).length
      },
      recentDocuments: documents.slice(0, 4).map(normalizeDocument)
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/documents") {
    const searchText = (url.searchParams.get("search") || "").trim().toLowerCase();
    const typeFilter = (url.searchParams.get("type") || "").trim().toLowerCase();
    const sortBy = (url.searchParams.get("sort") || "newest").trim().toLowerCase();
    const documents = getUserDocuments(store, user.id)
      .filter((document) => {
        if (typeFilter && document.documentType.toLowerCase() !== typeFilter) {
          return false;
        }

        if (!searchText) {
          return true;
        }

        return [
          document.title,
          document.documentType,
          document.fileName
        ]
          .join(" ")
          .toLowerCase()
          .includes(searchText);
      })
      .sort((a, b) => 0);

    const sortedDocuments = sortDocuments(documents, sortBy)
      .map(normalizeDocument);

    sendJson(response, 200, { documents: sortedDocuments });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/documents") {
    const body = await parseBody(request);
    const validationMessage = validateDocumentPayload(body, { requireFileFields: true });

    if (validationMessage) {
      sendJson(response, 400, { message: validationMessage });
      return;
    }

    const newDocument = {
      id: `DOC-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      ownerId: user.id,
      title: normalizeText(body.title),
      documentType: normalizeText(body.documentType),
      fileName: normalizeText(body.fileName),
      fileSize: Number(body.fileSize) || 0,
      fileType: normalizeText(body.fileType),
      fileDataUrl: body.fileDataUrl,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    store.documents.push(newDocument);
    writeStore(store);
    sendJson(response, 201, { document: normalizeDocument(newDocument) });
    return;
  }

  if (request.method === "GET" && /^\/api\/documents\/[^/]+$/.test(url.pathname)) {
    const documentId = url.pathname.split("/").pop();
    const document = getUserDocuments(store, user.id).find((item) => item.id === documentId);

    if (!document) {
      sendJson(response, 404, { message: "Document not found." });
      return;
    }

    sendJson(response, 200, { document: normalizeDocument(document) });
    return;
  }

  if (request.method === "PATCH" && /^\/api\/documents\/[^/]+$/.test(url.pathname)) {
    const documentId = url.pathname.split("/").pop();
    const document = getUserDocuments(store, user.id).find((item) => item.id === documentId);

    if (!document) {
      sendJson(response, 404, { message: "Document not found." });
      return;
    }

    const body = await parseBody(request);
    const validationMessage = validateDocumentPayload(body, { requireFileFields: false });

    if (validationMessage) {
      sendJson(response, 400, { message: validationMessage });
      return;
    }

    document.title = normalizeText(body.title);
    document.documentType = normalizeText(body.documentType);
    document.updatedAt = new Date().toISOString();

    writeStore(store);
    sendJson(response, 200, { document: normalizeDocument(document) });
    return;
  }

  if (request.method === "DELETE" && /^\/api\/documents\/[^/]+$/.test(url.pathname)) {
    const documentId = url.pathname.split("/").pop();
    const documentExists = getUserDocuments(store, user.id).some((item) => item.id === documentId);

    if (!documentExists) {
      sendJson(response, 404, { message: "Document not found." });
      return;
    }

    store.documents = store.documents.filter((document) => document.id !== documentId);
    writeStore(store);
    sendNoContent(response);
    return;
  }

  sendJson(response, 404, { message: "API route not found." });
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url);
      return;
    }

    serveStaticFile(url.pathname, response);
  } catch (error) {
    sendJson(response, 500, { message: error.message || "Internal server error." });
  }
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. The server may already be running at http://localhost:${PORT}.`);
    process.exit(1);
  }

  console.error(error.message || "Unable to start the server.");
  process.exit(1);
});

server.listen(PORT, () => {
  ensureStore();
  console.log(`Document Vault server is running on http://localhost:${PORT}`);
});
