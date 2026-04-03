import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class DocumentVaultServer {
    private static final int PORT = parsePort(System.getenv("PORT"), 3000);
    private static final Path ROOT_DIR = Path.of("").toAbsolutePath();
    private static final Path DATA_DIR = ROOT_DIR.resolve("data");
    private static final Path STORE_PATH = DATA_DIR.resolve("store.json");
    private static final long SESSION_MAX_AGE_SECONDS = 7L * 24 * 60 * 60;
    private static final long SESSION_MAX_AGE_MS = SESSION_MAX_AGE_SECONDS * 1000;
    private static final int MAX_JSON_BODY_BYTES = 6 * 1024 * 1024;
    private static final long MAX_DOCUMENT_FILE_SIZE = 2L * 1024 * 1024;
    private static final int MAX_NAME_LENGTH = 80;
    private static final int MAX_TITLE_LENGTH = 120;
    private static final int MAX_DOCUMENT_TYPE_LENGTH = 60;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Set<String> ALLOWED_FILE_TYPES = Set.of("application/pdf", "image/png", "image/jpeg", "image/webp", "image/avif");
    private static final Set<String> IDENTITY_TYPES = Set.of("aadhaar card", "ration card", "pan card", "voter id", "passport", "driving license");
    private static final Set<String> ACADEMIC_TYPES = Set.of("marksheet", "marklist", "certificate", "participation certificate", "resume");
    private static final Map<String, String> CONTENT_TYPES = Map.ofEntries(
        Map.entry(".html", "text/html; charset=utf-8"),
        Map.entry(".css", "text/css; charset=utf-8"),
        Map.entry(".js", "application/javascript; charset=utf-8"),
        Map.entry(".json", "application/json; charset=utf-8"),
        Map.entry(".png", "image/png"),
        Map.entry(".jpg", "image/jpeg"),
        Map.entry(".jpeg", "image/jpeg"),
        Map.entry(".svg", "image/svg+xml"),
        Map.entry(".ico", "image/x-icon"),
        Map.entry(".webp", "image/webp"),
        Map.entry(".avif", "image/avif")
    );
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, RateWindow> RATE_LIMITS = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        ensureStore();
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", new RootHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Document Vault Java server is running on http://localhost:" + PORT);
    }

    private static final class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                if (path.startsWith("/api/")) {
                    handleApi(exchange);
                    return;
                }
                serveStaticFile(exchange);
            } catch (BadRequestException error) {
                sendJson(exchange, error.statusCode, Map.of("message", error.getMessage()));
            } catch (Exception error) {
                sendJson(exchange, 500, Map.of("message", error.getMessage() == null ? "Internal server error." : error.getMessage()));
            } finally {
                exchange.close();
            }
        }
    }

    private static void serveStaticFile(HttpExchange exchange) throws IOException {
        String requestPath = exchange.getRequestURI().getPath();
        String safePath = "/".equals(requestPath) ? "/login.html" : requestPath;
        Path resolvedPath = ROOT_DIR.resolve("." + safePath).normalize();
        if (!resolvedPath.startsWith(ROOT_DIR) || Files.isDirectory(resolvedPath) || !Files.exists(resolvedPath)) {
            sendText(exchange, 404, "Not Found");
            return;
        }
        String extension = extensionOf(resolvedPath.getFileName().toString());
        byte[] bytes = Files.readAllBytes(resolvedPath);
        Headers headers = exchange.getResponseHeaders();
        applySecurityHeaders(headers);
        headers.set("Content-Type", CONTENT_TYPES.getOrDefault(extension, "application/octet-stream"));
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static void ensureStore() throws IOException {
        if (!Files.exists(DATA_DIR)) {
            Files.createDirectories(DATA_DIR);
        }
        if (!Files.exists(STORE_PATH)) {
            Map<String, Object> initial = new LinkedHashMap<>();
            initial.put("users", new ArrayList<>());
            initial.put("documents", new ArrayList<>());
            initial.put("sessions", new ArrayList<>());
            Files.writeString(STORE_PATH, Json.stringify(initial), StandardCharsets.UTF_8);
        }
    }

    private static Store readStore() throws IOException {
        ensureStore();
        Object parsed = Json.parse(Files.readString(STORE_PATH, StandardCharsets.UTF_8));
        if (!(parsed instanceof Map<?, ?> root)) {
            throw new IOException("Store file is invalid.");
        }

        Store store = new Store();
        for (Object item : listValue(root.get("users"))) {
            if (item instanceof Map<?, ?> data) {
                User user = new User();
                user.id = stringValue(data.get("id"));
                user.name = stringValue(data.get("name"));
                user.email = stringValue(data.get("email"));
                user.password = stringValue(data.get("password"));
                user.createdAt = stringValue(data.get("createdAt"));
                if (!user.id.isBlank()) {
                    store.users.add(user);
                }
            }
        }

        for (Object item : listValue(root.get("documents"))) {
            if (item instanceof Map<?, ?> data) {
                DocumentRecord document = new DocumentRecord();
                document.id = stringValue(data.get("id"));
                document.ownerId = stringValue(data.get("ownerId"));
                document.title = stringValue(data.get("title"));
                document.documentType = stringValue(data.get("documentType"));
                document.fileName = stringValue(data.get("fileName"));
                document.fileSize = toLong(data.get("fileSize"));
                document.fileType = stringValue(data.get("fileType"));
                document.fileDataUrl = stringValue(data.get("fileDataUrl"));
                document.createdAt = stringValue(data.get("createdAt"));
                document.updatedAt = stringValue(data.get("updatedAt"));
                if (document.updatedAt.isBlank()) {
                    document.updatedAt = document.createdAt;
                }
                if (!document.id.isBlank()) {
                    store.documents.add(document);
                }
            }
        }

        long now = System.currentTimeMillis();
        boolean changed = false;
        for (Object item : listValue(root.get("sessions"))) {
            if (item instanceof Map<?, ?> data) {
                SessionRecord session = new SessionRecord();
                session.id = stringValue(data.get("id"));
                session.userId = stringValue(data.get("userId"));
                session.createdAt = stringValue(data.get("createdAt"));
                if (!session.id.isBlank() && parseIsoMillis(session.createdAt) + SESSION_MAX_AGE_MS > now) {
                    store.sessions.add(session);
                } else {
                    changed = true;
                }
            }
        }

        if (changed) {
            writeStore(store);
        }
        return store;
    }

    private static void writeStore(Store store) throws IOException {
        Map<String, Object> root = new LinkedHashMap<>();
        List<Object> users = new ArrayList<>();
        for (User user : store.users) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", user.id);
            item.put("name", user.name);
            item.put("email", user.email);
            item.put("password", user.password);
            item.put("createdAt", user.createdAt);
            users.add(item);
        }

        List<Object> documents = new ArrayList<>();
        for (DocumentRecord document : store.documents) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", document.id);
            item.put("ownerId", document.ownerId);
            item.put("title", document.title);
            item.put("documentType", document.documentType);
            item.put("fileName", document.fileName);
            item.put("fileSize", document.fileSize);
            item.put("fileType", document.fileType);
            item.put("fileDataUrl", document.fileDataUrl);
            item.put("createdAt", document.createdAt);
            item.put("updatedAt", document.updatedAt);
            documents.add(item);
        }

        List<Object> sessions = new ArrayList<>();
        for (SessionRecord session : store.sessions) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", session.id);
            item.put("userId", session.userId);
            item.put("createdAt", session.createdAt);
            sessions.add(item);
        }

        root.put("users", users);
        root.put("documents", documents);
        root.put("sessions", sessions);
        Files.writeString(STORE_PATH, Json.stringify(root), StandardCharsets.UTF_8);
    }

    private static void handleApi(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String method = exchange.getRequestMethod();
        String path = uri.getPath();
        Store store = readStore();
        User user = getSessionUser(exchange, store);
        if ("GET".equals(method) && "/api/health".equals(path)) {
            sendJson(exchange, 200, Map.of("status", "ok", "timestamp", nowIso()));
            return;
        }
        if ("GET".equals(method) && "/api/session".equals(path)) {
            if (user == null) {
                sendJson(exchange, 401, Map.of("message", "Not authenticated."));
                return;
            }
            sendJson(exchange, 200, Map.of("user", toSafeUser(user)));
            return;
        }
        if ("POST".equals(method) && "/api/signup".equals(path)) {
            if (isRateLimited(exchange, "signup", 8, 10 * 60 * 1000L)) {
                sendJson(exchange, 429, Map.of("message", "Too many signup attempts. Please wait and try again."));
                return;
            }
            Map<String, Object> body = parseJsonBody(exchange);
            String name = normalizeText(body.get("name"));
            String email = normalizeText(body.get("email")).toLowerCase(Locale.ROOT);
            String password = Objects.toString(body.get("password"), "");
            if (name.isBlank() || email.isBlank() || password.isBlank()) {
                sendJson(exchange, 400, Map.of("message", "Name, email, and password are required."));
                return;
            }
            if (name.length() > MAX_NAME_LENGTH) {
                sendJson(exchange, 400, Map.of("message", "Name must be " + MAX_NAME_LENGTH + " characters or fewer."));
                return;
            }
            if (!EMAIL_PATTERN.matcher(email).matches()) {
                sendJson(exchange, 400, Map.of("message", "Please enter a valid email address."));
                return;
            }
            if (password.length() < 6) {
                sendJson(exchange, 400, Map.of("message", "Password must be at least 6 characters."));
                return;
            }
            if (store.findUserByEmail(email) != null) {
                sendJson(exchange, 409, Map.of("message", "An account with this email already exists."));
                return;
            }
            User newUser = new User();
            newUser.id = "USER-" + System.currentTimeMillis() + "-" + RANDOM.nextInt(1000);
            newUser.name = name;
            newUser.email = email;
            newUser.password = hashPassword(password);
            newUser.createdAt = nowIso();
            store.users.add(newUser);
            String sessionId = createSession(store, newUser);
            writeStore(store);
            sendJson(exchange, 201, Map.of("user", toSafeUser(newUser)), Map.of("Set-Cookie", createSessionCookie(sessionId)));
            return;
        }
        if ("POST".equals(method) && "/api/login".equals(path)) {
            if (isRateLimited(exchange, "login", 12, 10 * 60 * 1000L)) {
                sendJson(exchange, 429, Map.of("message", "Too many login attempts. Please wait and try again."));
                return;
            }
            Map<String, Object> body = parseJsonBody(exchange);
            String email = normalizeText(body.get("email")).toLowerCase(Locale.ROOT);
            String password = Objects.toString(body.get("password"), "");
            if (!EMAIL_PATTERN.matcher(email).matches() || password.isBlank()) {
                sendJson(exchange, 400, Map.of("message", "Valid email and password are required."));
                return;
            }
            User existingUser = store.findUserByEmail(email);
            if (existingUser == null || !verifyPassword(password, existingUser.password)) {
                sendJson(exchange, 401, Map.of("message", "Invalid email or password."));
                return;
            }
            if (!existingUser.password.startsWith("pbkdf2$")) {
                existingUser.password = hashPassword(password);
            }
            String sessionId = createSession(store, existingUser);
            writeStore(store);
            sendJson(exchange, 200, Map.of("user", toSafeUser(existingUser)), Map.of("Set-Cookie", createSessionCookie(sessionId)));
            return;
        }
        if ("POST".equals(method) && "/api/logout".equals(path)) {
            clearSession(exchange, store);
            writeStore(store);
            sendNoContent(exchange, Map.of("Set-Cookie", clearSessionCookie()));
            return;
        }
        if (user == null) {
            sendJson(exchange, 401, Map.of("message", "Please login to continue."));
            return;
        }
        if ("GET".equals(method) && "/api/dashboard".equals(path)) {
            List<DocumentRecord> documents = sortDocuments(store.documentsForUser(user.id), "newest");
            long identityCount = documents.stream().filter(document -> IDENTITY_TYPES.contains(document.documentType.toLowerCase(Locale.ROOT))).count();
            long academicCount = documents.stream().filter(document -> ACADEMIC_TYPES.contains(document.documentType.toLowerCase(Locale.ROOT))).count();
            List<Object> recentDocuments = new ArrayList<>();
            for (int index = 0; index < Math.min(4, documents.size()); index++) {
                recentDocuments.add(normalizeDocument(documents.get(index)));
            }
            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("totalDocuments", documents.size());
            stats.put("identityDocuments", identityCount);
            stats.put("academicDocuments", academicCount);
            sendJson(exchange, 200, Map.of("stats", stats, "recentDocuments", recentDocuments));
            return;
        }
        if ("GET".equals(method) && "/api/documents".equals(path)) {
            Map<String, String> query = parseQuery(uri.getRawQuery());
            String searchText = query.getOrDefault("search", "").trim().toLowerCase(Locale.ROOT);
            String typeFilter = query.getOrDefault("type", "").trim().toLowerCase(Locale.ROOT);
            String sortBy = query.getOrDefault("sort", "newest").trim().toLowerCase(Locale.ROOT);
            List<DocumentRecord> filtered = new ArrayList<>();
            for (DocumentRecord document : store.documentsForUser(user.id)) {
                if (!typeFilter.isBlank() && !document.documentType.toLowerCase(Locale.ROOT).equals(typeFilter)) {
                    continue;
                }
                if (!searchText.isBlank()) {
                    String searchable = (document.title + " " + document.documentType + " " + document.fileName).toLowerCase(Locale.ROOT);
                    if (!searchable.contains(searchText)) {
                        continue;
                    }
                }
                filtered.add(document);
            }
            List<Object> normalized = new ArrayList<>();
            for (DocumentRecord document : sortDocuments(filtered, sortBy)) {
                normalized.add(normalizeDocument(document));
            }
            sendJson(exchange, 200, Map.of("documents", normalized));
            return;
        }
        if ("POST".equals(method) && "/api/documents".equals(path)) {
            Map<String, Object> body = parseJsonBody(exchange);
            String validationMessage = validateDocumentPayload(body, true);
            if (validationMessage != null) {
                sendJson(exchange, 400, Map.of("message", validationMessage));
                return;
            }
            DocumentRecord document = new DocumentRecord();
            document.id = "DOC-" + System.currentTimeMillis() + "-" + RANDOM.nextInt(1000);
            document.ownerId = user.id;
            document.title = normalizeText(body.get("title"));
            document.documentType = normalizeText(body.get("documentType"));
            document.fileName = normalizeText(body.get("fileName"));
            document.fileSize = toLong(body.get("fileSize"));
            document.fileType = normalizeText(body.get("fileType"));
            document.fileDataUrl = Objects.toString(body.get("fileDataUrl"), "");
            document.createdAt = nowIso();
            document.updatedAt = document.createdAt;
            store.documents.add(document);
            writeStore(store);
            sendJson(exchange, 201, Map.of("document", normalizeDocument(document)));
            return;
        }
        if (path.matches("^/api/documents/[^/]+$")) {
            String documentId = path.substring(path.lastIndexOf('/') + 1);
            DocumentRecord document = store.documentForUser(user.id, documentId);
            if (document == null) {
                sendJson(exchange, 404, Map.of("message", "Document not found."));
                return;
            }
            if ("GET".equals(method)) {
                sendJson(exchange, 200, Map.of("document", normalizeDocument(document)));
                return;
            }
            if ("PATCH".equals(method)) {
                Map<String, Object> body = parseJsonBody(exchange);
                String validationMessage = validateDocumentPayload(body, false);
                if (validationMessage != null) {
                    sendJson(exchange, 400, Map.of("message", validationMessage));
                    return;
                }
                document.title = normalizeText(body.get("title"));
                document.documentType = normalizeText(body.get("documentType"));
                document.updatedAt = nowIso();
                writeStore(store);
                sendJson(exchange, 200, Map.of("document", normalizeDocument(document)));
                return;
            }
            if ("DELETE".equals(method)) {
                store.documents.remove(document);
                writeStore(store);
                sendNoContent(exchange);
                return;
            }
        }
        sendJson(exchange, 404, Map.of("message", "API route not found."));
    }

    private static Map<String, Object> parseJsonBody(HttpExchange exchange) throws IOException {
        byte[] bytes = readRequestBody(exchange.getRequestBody(), MAX_JSON_BODY_BYTES);
        if (bytes.length == 0) {
            return new LinkedHashMap<>();
        }
        Object parsed = Json.parse(new String(bytes, StandardCharsets.UTF_8));
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new BadRequestException(400, "Invalid JSON body.");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            result.put(Objects.toString(entry.getKey(), ""), entry.getValue());
        }
        return result;
    }

    private static byte[] readRequestBody(InputStream inputStream, int limitBytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        int total = 0;
        while ((read = inputStream.read(chunk)) != -1) {
            total += read;
            if (total > limitBytes) {
                throw new BadRequestException(413, "Request body is too large.");
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    private static User getSessionUser(HttpExchange exchange, Store store) throws IOException {
        String sessionId = parseCookies(exchange.getRequestHeaders().getFirst("Cookie")).get("sid");
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        SessionRecord session = store.findSession(sessionId);
        if (session == null) {
            return null;
        }
        if (parseIsoMillis(session.createdAt) + SESSION_MAX_AGE_MS <= System.currentTimeMillis()) {
            store.sessions.remove(session);
            writeStore(store);
            return null;
        }
        return store.findUserById(session.userId);
    }

    private static String createSession(Store store, User user) {
        String sessionId = UUID.randomUUID().toString();
        store.sessions.removeIf(session -> user.id.equals(session.userId));
        SessionRecord session = new SessionRecord();
        session.id = sessionId;
        session.userId = user.id;
        session.createdAt = nowIso();
        store.sessions.add(session);
        return sessionId;
    }

    private static void clearSession(HttpExchange exchange, Store store) {
        String sessionId = parseCookies(exchange.getRequestHeaders().getFirst("Cookie")).get("sid");
        if (sessionId != null) {
            store.sessions.removeIf(session -> sessionId.equals(session.id));
        }
    }

    private static Map<String, Object> toSafeUser(User user) {
        Map<String, Object> safe = new LinkedHashMap<>();
        safe.put("id", user.id);
        safe.put("name", user.name);
        safe.put("email", user.email);
        safe.put("createdAt", user.createdAt);
        return safe;
    }

    private static Map<String, Object> normalizeDocument(DocumentRecord document) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("id", document.id);
        normalized.put("ownerId", document.ownerId);
        normalized.put("title", document.title);
        normalized.put("documentType", document.documentType);
        normalized.put("fileName", document.fileName);
        normalized.put("fileSize", document.fileSize);
        normalized.put("fileType", document.fileType);
        normalized.put("fileDataUrl", document.fileDataUrl);
        normalized.put("createdAt", document.createdAt);
        normalized.put("updatedAt", document.updatedAt == null || document.updatedAt.isBlank() ? document.createdAt : document.updatedAt);
        return normalized;
    }

    private static List<DocumentRecord> sortDocuments(List<DocumentRecord> documents, String sortKey) {
        List<DocumentRecord> items = new ArrayList<>(documents);
        if ("oldest".equals(sortKey)) {
            items.sort(Comparator.comparingLong(document -> parseIsoMillis(document.createdAt)));
            return items;
        }
        if ("title-asc".equals(sortKey)) {
            items.sort(Comparator.comparing(document -> document.title.toLowerCase(Locale.ROOT)));
            return items;
        }
        if ("type-asc".equals(sortKey)) {
            items.sort(Comparator.comparing(document -> document.documentType.toLowerCase(Locale.ROOT)));
            return items;
        }
        items.sort((left, right) -> Long.compare(parseIsoMillis(right.createdAt), parseIsoMillis(left.createdAt)));
        return items;
    }

    private static String validateDocumentPayload(Map<String, Object> body, boolean requireFileFields) {
        String title = normalizeText(body.get("title"));
        String documentType = normalizeText(body.get("documentType"));
        String fileName = normalizeText(body.get("fileName"));
        String fileType = normalizeText(body.get("fileType"));
        String fileDataUrl = Objects.toString(body.getOrDefault("fileDataUrl", ""), "");
        long fileSize = toLong(body.get("fileSize"));
        if (title.isBlank() || documentType.isBlank()) {
            return "Title and document type are required.";
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            return "Title must be " + MAX_TITLE_LENGTH + " characters or fewer.";
        }
        if (documentType.length() > MAX_DOCUMENT_TYPE_LENGTH) {
            return "Document type must be " + MAX_DOCUMENT_TYPE_LENGTH + " characters or fewer.";
        }
        if (!requireFileFields) {
            return null;
        }
        if (fileName.isBlank() || fileType.isBlank() || fileDataUrl.isBlank()) {
            return "fileName, fileType, and fileDataUrl are required.";
        }
        if (!ALLOWED_FILE_TYPES.contains(fileType)) {
            return "Only PDF, PNG, JPG, WEBP, and AVIF files are supported.";
        }
        if (fileSize <= 0 || fileSize > MAX_DOCUMENT_FILE_SIZE) {
            return "Please upload a file smaller than 2 MB.";
        }
        String prefix = "data:" + fileType + ";base64,";
        if (!fileDataUrl.startsWith(prefix)) {
            return "Invalid file data.";
        }
        try {
            Base64.getDecoder().decode(fileDataUrl.substring(prefix.length()));
        } catch (IllegalArgumentException error) {
            return "Invalid file data.";
        }
        return null;
    }

    private static boolean verifyPassword(String password, String storedValue) {
        if (storedValue == null || storedValue.isBlank()) {
            return false;
        }
        if (storedValue.startsWith("pbkdf2$")) {
            return verifyPbkdf2Password(password, storedValue);
        }
        if (storedValue.contains(":")) {
            return verifyLegacyScryptPassword(password, storedValue);
        }
        return storedValue.equals(password);
    }

    private static String hashPassword(String password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return "pbkdf2$" + PBKDF2_ITERATIONS + "$" + hex(salt) + "$" + hex(pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS, 32));
    }

    private static boolean verifyPbkdf2Password(String password, String storedValue) {
        try {
            String[] parts = storedValue.split("\\$");
            byte[] expected = hexToBytes(parts[3]);
            byte[] actual = pbkdf2(password.toCharArray(), hexToBytes(parts[2]), Integer.parseInt(parts[1]), expected.length);
            return constantTimeEquals(expected, actual);
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int length) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, length * 8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("Unable to hash password.", error);
        }
    }

    private static boolean verifyLegacyScryptPassword(String password, String storedValue) {
        try {
            List<String> command = Arrays.asList("node", "-e", "const crypto=require('crypto'); const stored=process.argv[1]; const password=process.argv[2]; const [salt,hash]=stored.split(':'); const computed=crypto.scryptSync(password,salt,64).toString('hex'); process.stdout.write(hash===computed?'true':'false');", storedValue, password);
            Process process = new ProcessBuilder(command).directory(ROOT_DIR.toFile()).redirectErrorStream(true).start();
            String output;
            try (InputStream inputStream = process.getInputStream()) {
                output = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
            return process.waitFor() == 0 && "true".equals(output);
        } catch (Exception error) {
            return false;
        }
    }

    private static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        int result = 0;
        for (int index = 0; index < left.length; index++) {
            result |= left[index] ^ right[index];
        }
        return result == 0;
    }

    private static boolean isRateLimited(HttpExchange exchange, String scope, int limit, long windowMs) {
        String key = scope + ":" + clientAddress(exchange);
        long now = System.currentTimeMillis();
        RateWindow window = RATE_LIMITS.computeIfAbsent(key, ignored -> new RateWindow());
        synchronized (window) {
            if (window.expiresAt <= now) {
                window.count = 1;
                window.expiresAt = now + windowMs;
                return false;
            }
            if (window.count >= limit) {
                return true;
            }
            window.count += 1;
            return false;
        }
    }

    private static String clientAddress(HttpExchange exchange) {
        String forwarded = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private static void sendJson(HttpExchange exchange, int statusCode, Object payload) throws IOException {
        sendJson(exchange, statusCode, payload, Collections.emptyMap());
    }

    private static void sendJson(HttpExchange exchange, int statusCode, Object payload, Map<String, String> extraHeaders) throws IOException {
        byte[] bytes = Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        applySecurityHeaders(headers);
        headers.set("Content-Type", "application/json; charset=utf-8");
        for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
            headers.add(entry.getKey(), entry.getValue());
        }
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static void sendNoContent(HttpExchange exchange) throws IOException {
        sendNoContent(exchange, Collections.emptyMap());
    }

    private static void sendNoContent(HttpExchange exchange, Map<String, String> extraHeaders) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        applySecurityHeaders(headers);
        for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
            headers.add(entry.getKey(), entry.getValue());
        }
        exchange.sendResponseHeaders(204, -1);
    }

    private static void sendText(HttpExchange exchange, int statusCode, String message) throws IOException {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        applySecurityHeaders(headers);
        headers.set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static void applySecurityHeaders(Headers headers) {
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
        headers.set("Cross-Origin-Opener-Policy", "same-origin");
        headers.set("Cross-Origin-Resource-Policy", "same-origin");
        headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    }

    private static String createSessionCookie(String sessionId) {
        return "sid=" + urlEncode(sessionId) + "; HttpOnly; Path=/; SameSite=Lax; Max-Age=" + SESSION_MAX_AGE_SECONDS;
    }

    private static String clearSessionCookie() {
        return "sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0";
    }

    private static Map<String, String> parseCookies(String cookieHeader) {
        Map<String, String> cookies = new HashMap<>();
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return cookies;
        }
        for (String part : cookieHeader.split(";")) {
            String[] pieces = part.trim().split("=", 2);
            if (pieces.length == 2) {
                cookies.put(pieces[0], urlDecode(pieces[1]));
            }
        }
        return cookies;
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> query = new HashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return query;
        }
        for (String pair : rawQuery.split("&")) {
            String[] pieces = pair.split("=", 2);
            query.put(urlDecode(pieces[0]), pieces.length > 1 ? urlDecode(pieces[1]) : "");
        }
        return query;
    }

    private static String normalizeText(Object value) {
        return Objects.toString(value, "").trim();
    }

    private static List<Object> listValue(Object value) {
        return value instanceof List<?> list ? new ArrayList<>(list) : new ArrayList<>();
    }

    private static String stringValue(Object value) {
        return Objects.toString(value, "");
    }

    private static long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(Objects.toString(value, "0"));
        } catch (NumberFormatException error) {
            return 0;
        }
    }

    private static String nowIso() {
        return Instant.now().toString();
    }

    private static long parseIsoMillis(String value) {
        try {
            return Instant.parse(value).toEpochMilli();
        } catch (DateTimeParseException error) {
            return 0;
        }
    }

    private static String extensionOf(String filename) {
        int index = filename.lastIndexOf('.');
        return index == -1 ? "" : filename.substring(index).toLowerCase(Locale.ROOT);
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private static byte[] hexToBytes(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int index = 0; index < bytes.length; index++) {
            int offset = index * 2;
            bytes[index] = (byte) Integer.parseInt(value.substring(offset, offset + 2), 16);
        }
        return bytes;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static int parsePort(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException error) {
            return fallback;
        }
    }

    private static final class Store {
        final List<User> users = new ArrayList<>();
        final List<DocumentRecord> documents = new ArrayList<>();
        final List<SessionRecord> sessions = new ArrayList<>();

        User findUserByEmail(String email) {
            for (User user : users) {
                if (user.email.equals(email)) {
                    return user;
                }
            }
            return null;
        }

        User findUserById(String userId) {
            for (User user : users) {
                if (user.id.equals(userId)) {
                    return user;
                }
            }
            return null;
        }

        SessionRecord findSession(String sessionId) {
            for (SessionRecord session : sessions) {
                if (session.id.equals(sessionId)) {
                    return session;
                }
            }
            return null;
        }

        List<DocumentRecord> documentsForUser(String userId) {
            List<DocumentRecord> results = new ArrayList<>();
            for (DocumentRecord document : documents) {
                if (userId.equals(document.ownerId)) {
                    results.add(document);
                }
            }
            return results;
        }

        DocumentRecord documentForUser(String userId, String documentId) {
            for (DocumentRecord document : documents) {
                if (userId.equals(document.ownerId) && documentId.equals(document.id)) {
                    return document;
                }
            }
            return null;
        }
    }

    private static final class User {
        String id = "";
        String name = "";
        String email = "";
        String password = "";
        String createdAt = "";
    }

    private static final class DocumentRecord {
        String id = "";
        String ownerId = "";
        String title = "";
        String documentType = "";
        String fileName = "";
        long fileSize;
        String fileType = "";
        String fileDataUrl = "";
        String createdAt = "";
        String updatedAt = "";
    }

    private static final class SessionRecord {
        String id = "";
        String userId = "";
        String createdAt = "";
    }

    private static final class RateWindow {
        int count = 0;
        long expiresAt = 0;
    }

    private static final class BadRequestException extends IOException {
        final int statusCode;

        BadRequestException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }
    }

    private static final class Json {
        static Object parse(String source) {
            Parser parser = new Parser(source);
            Object value = parser.parseValue();
            parser.skipWhitespace();
            if (!parser.isAtEnd()) {
                throw new IllegalArgumentException("Invalid JSON body.");
            }
            return value;
        }

        static String stringify(Object value) {
            StringBuilder builder = new StringBuilder();
            writeValue(builder, value);
            return builder.toString();
        }

        private static void writeValue(StringBuilder builder, Object value) {
            if (value == null) {
                builder.append("null");
                return;
            }
            if (value instanceof String text) {
                builder.append('"');
                for (int index = 0; index < text.length(); index++) {
                    char character = text.charAt(index);
                    switch (character) {
                        case '\\' -> builder.append("\\\\");
                        case '"' -> builder.append("\\\"");
                        case '\b' -> builder.append("\\b");
                        case '\f' -> builder.append("\\f");
                        case '\n' -> builder.append("\\n");
                        case '\r' -> builder.append("\\r");
                        case '\t' -> builder.append("\\t");
                        default -> {
                            if (character < 0x20) {
                                builder.append(String.format("\\u%04x", (int) character));
                            } else {
                                builder.append(character);
                            }
                        }
                    }
                }
                builder.append('"');
                return;
            }
            if (value instanceof Number || value instanceof Boolean) {
                builder.append(value);
                return;
            }
            if (value instanceof Map<?, ?> map) {
                builder.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        builder.append(',');
                    }
                    first = false;
                    writeValue(builder, Objects.toString(entry.getKey(), ""));
                    builder.append(':');
                    writeValue(builder, entry.getValue());
                }
                builder.append('}');
                return;
            }
            if (value instanceof Iterable<?> iterable) {
                builder.append('[');
                boolean first = true;
                for (Object item : iterable) {
                    if (!first) {
                        builder.append(',');
                    }
                    first = false;
                    writeValue(builder, item);
                }
                builder.append(']');
                return;
            }
            writeValue(builder, value.toString());
        }

        private static final class Parser {
            private final String source;
            private int index = 0;

            Parser(String source) {
                this.source = source == null ? "" : source;
            }

            Object parseValue() {
                skipWhitespace();
                if (isAtEnd()) {
                    throw new IllegalArgumentException("Invalid JSON body.");
                }
                char current = source.charAt(index);
                return switch (current) {
                    case '{' -> parseObject();
                    case '[' -> parseArray();
                    case '"' -> parseString();
                    case 't' -> parseLiteral("true", Boolean.TRUE);
                    case 'f' -> parseLiteral("false", Boolean.FALSE);
                    case 'n' -> parseLiteral("null", null);
                    default -> parseNumber();
                };
            }

            Map<String, Object> parseObject() {
                Map<String, Object> object = new LinkedHashMap<>();
                index++;
                skipWhitespace();
                if (peek('}')) {
                    index++;
                    return object;
                }
                while (true) {
                    skipWhitespace();
                    String key = parseString();
                    skipWhitespace();
                    expect(':');
                    object.put(key, parseValue());
                    skipWhitespace();
                    if (peek('}')) {
                        index++;
                        return object;
                    }
                    expect(',');
                }
            }

            List<Object> parseArray() {
                List<Object> array = new ArrayList<>();
                index++;
                skipWhitespace();
                if (peek(']')) {
                    index++;
                    return array;
                }
                while (true) {
                    array.add(parseValue());
                    skipWhitespace();
                    if (peek(']')) {
                        index++;
                        return array;
                    }
                    expect(',');
                }
            }

            String parseString() {
                expect('"');
                StringBuilder builder = new StringBuilder();
                while (!isAtEnd()) {
                    char current = source.charAt(index++);
                    if (current == '"') {
                        return builder.toString();
                    }
                    if (current == '\\') {
                        char escaped = source.charAt(index++);
                        switch (escaped) {
                            case '"' -> builder.append('"');
                            case '\\' -> builder.append('\\');
                            case '/' -> builder.append('/');
                            case 'b' -> builder.append('\b');
                            case 'f' -> builder.append('\f');
                            case 'n' -> builder.append('\n');
                            case 'r' -> builder.append('\r');
                            case 't' -> builder.append('\t');
                            case 'u' -> {
                                builder.append((char) Integer.parseInt(source.substring(index, index + 4), 16));
                                index += 4;
                            }
                            default -> throw new IllegalArgumentException("Invalid JSON body.");
                        }
                    } else {
                        builder.append(current);
                    }
                }
                throw new IllegalArgumentException("Invalid JSON body.");
            }

            Object parseLiteral(String literal, Object value) {
                if (!source.startsWith(literal, index)) {
                    throw new IllegalArgumentException("Invalid JSON body.");
                }
                index += literal.length();
                return value;
            }

            Number parseNumber() {
                int start = index;
                if (peek('-')) {
                    index++;
                }
                while (!isAtEnd() && Character.isDigit(source.charAt(index))) {
                    index++;
                }
                if (!isAtEnd() && source.charAt(index) == '.') {
                    index++;
                    while (!isAtEnd() && Character.isDigit(source.charAt(index))) {
                        index++;
                    }
                }
                if (!isAtEnd() && (source.charAt(index) == 'e' || source.charAt(index) == 'E')) {
                    index++;
                    if (!isAtEnd() && (source.charAt(index) == '+' || source.charAt(index) == '-')) {
                        index++;
                    }
                    while (!isAtEnd() && Character.isDigit(source.charAt(index))) {
                        index++;
                    }
                }
                String number = source.substring(start, index);
                return number.contains(".") || number.contains("e") || number.contains("E") ? Double.parseDouble(number) : Long.parseLong(number);
            }

            void skipWhitespace() {
                while (!isAtEnd() && Character.isWhitespace(source.charAt(index))) {
                    index++;
                }
            }

            void expect(char expected) {
                skipWhitespace();
                if (isAtEnd() || source.charAt(index) != expected) {
                    throw new IllegalArgumentException("Invalid JSON body.");
                }
                index++;
            }

            boolean peek(char expected) {
                return !isAtEnd() && source.charAt(index) == expected;
            }

            boolean isAtEnd() {
                return index >= source.length();
            }
        }
    }
}
