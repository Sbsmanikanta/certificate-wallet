const API_BASE = "/api";
const SUPPORTED_UPLOAD_TYPES = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/avif"
]);

function formatFileSize(bytes) {
  if (!bytes && bytes !== 0) {
    return "Unknown size";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDateTime(value) {
  if (!value) {
    return "Unknown date";
  }

  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showMessage(element, message, type) {
  if (!element) {
    return;
  }

  element.textContent = message;
  element.className = `form-message ${type}`;
}

async function apiRequest(path, options = {}) {
  let response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      },
      ...options
    });
  } catch (error) {
    if (window.location.protocol === "file:") {
      throw new Error("Open this project through the backend server at http://localhost:3000, not by double-clicking the HTML file.");
    }

    throw new Error("Cannot connect to the backend server. Start it with `node server.js` or `npm.cmd start`, then open http://localhost:3000.");
  }

  const isJson = response.headers.get("content-type")?.includes("application/json");
  const payload = isJson ? await response.json() : null;

  if (!response.ok) {
    throw new Error(payload?.message || "Something went wrong.");
  }

  return payload;
}

let currentSessionPromise = null;

async function getCurrentUser() {
  if (!currentSessionPromise) {
    currentSessionPromise = apiRequest("/session")
      .then((payload) => payload.user)
      .catch(() => null);
  }

  return currentSessionPromise;
}

function resetCurrentUser() {
  currentSessionPromise = null;
}

async function requireAuth() {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "login.html";
    return null;
  }

  return user;
}

async function handleLogout() {
  try {
    await apiRequest("/logout", { method: "POST" });
  } catch (error) {
    // Even if the server session is already gone, move the user to login.
  } finally {
    resetCurrentUser();
    window.location.href = "login.html";
  }
}

function bindLogoutButtons() {
  document.querySelectorAll("[data-action='logout']").forEach((button) => {
    button.addEventListener("click", handleLogout);
  });
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Unable to read the selected file."));
    reader.readAsDataURL(file);
  });
}

function isImageDocument(document) {
  return Boolean(document.fileType && document.fileType.startsWith("image/"));
}

function isPdfDocument(document) {
  return document.fileType === "application/pdf";
}

async function openDocumentPreview(documentId) {
  const user = await getCurrentUser();
  if (!user) {
    return;
  }

  try {
    const payload = await apiRequest(`/documents/${documentId}`);
    const document = payload.document;
    const previewWindow = window.open("", "_blank");

    if (!previewWindow || !document || !document.fileDataUrl) {
      return;
    }

    const safeTitle = document.title.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    if (isImageDocument(document)) {
      previewWindow.document.write(`
        <title>${safeTitle}</title>
        <style>
          body { margin: 0; background: #0f172a; display: grid; place-items: center; min-height: 100vh; }
          img { max-width: 96vw; max-height: 96vh; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.35); }
        </style>
        <img src="${document.fileDataUrl}" alt="${safeTitle}">
      `);
      return;
    }

    if (isPdfDocument(document)) {
      previewWindow.document.write(`
        <title>${safeTitle}</title>
        <style>html, body, iframe { margin: 0; width: 100%; height: 100%; }</style>
        <iframe src="${document.fileDataUrl}" title="${safeTitle}"></iframe>
      `);
      return;
    }

    previewWindow.document.write(`
      <title>${safeTitle}</title>
      <body style="font-family: Segoe UI, sans-serif; padding: 24px;">
        <h1>${safeTitle}</h1>
        <p>This file type cannot be previewed here. Please use download.</p>
        <a href="${document.fileDataUrl}" download="${document.fileName}">Download file</a>
      </body>
    `);
  } catch (error) {
    window.alert(error.message);
  }
}

function initSignupPage() {
  const form = document.getElementById("signupForm");
  const message = document.getElementById("signupMessage");

  if (!form) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const name = document.getElementById("signupName").value.trim();
    const email = document.getElementById("signupEmail").value.trim().toLowerCase();
    const password = document.getElementById("signupPassword").value;
    const confirmPassword = document.getElementById("signupConfirmPassword").value;

    if (!name || !email || !password || !confirmPassword) {
      showMessage(message, "Please fill in all fields.", "error");
      return;
    }

    if (name.length > 80) {
      showMessage(message, "Name must be 80 characters or fewer.", "error");
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showMessage(message, "Please enter a valid email address.", "error");
      return;
    }

    if (password.length < 6) {
      showMessage(message, "Password must be at least 6 characters.", "error");
      return;
    }

    if (password !== confirmPassword) {
      showMessage(message, "Passwords do not match.", "error");
      return;
    }

    try {
      const payload = await apiRequest("/signup", {
        method: "POST",
        body: JSON.stringify({ name, email, password })
      });

      resetCurrentUser();
      currentSessionPromise = Promise.resolve(payload.user);
      showMessage(message, "Account created successfully. Opening your welcome page...", "success");
      form.reset();

      setTimeout(() => {
        window.location.href = "welcome.html";
      }, 900);
    } catch (error) {
      showMessage(message, error.message, "error");
    }
  });
}

function initLoginPage() {
  const form = document.getElementById("loginForm");
  const message = document.getElementById("loginMessage");

  if (!form) {
    return;
  }

  getCurrentUser().then((user) => {
    if (user) {
      window.location.href = "Dashboard.html";
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("loginEmail").value.trim().toLowerCase();
    const password = document.getElementById("loginPassword").value;

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showMessage(message, "Please enter a valid email address.", "error");
      return;
    }

    if (!password) {
      showMessage(message, "Password is required.", "error");
      return;
    }

    try {
      const payload = await apiRequest("/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
      });

      resetCurrentUser();
      currentSessionPromise = Promise.resolve(payload.user);
      showMessage(message, "Login successful. Opening dashboard...", "success");

      setTimeout(() => {
        window.location.href = "Dashboard.html";
      }, 800);
    } catch (error) {
      showMessage(message, error.message, "error");
    }
  });
}

function initWelcomePage() {
  const welcomeName = document.getElementById("welcomeUserName");
  if (!welcomeName) {
    return;
  }

  requireAuth().then((user) => {
    if (!user) {
      return;
    }

    bindLogoutButtons();
    welcomeName.textContent = user.name;
  });
}

function initDashboardPage() {
  const welcome = document.getElementById("welcomeName");
  if (!welcome) {
    return;
  }

  requireAuth().then(async (user) => {
    if (!user) {
      return;
    }

    bindLogoutButtons();

    const totalDocuments = document.getElementById("totalDocuments");
    const identityDocuments = document.getElementById("identityDocuments");
    const academicDocuments = document.getElementById("academicDocuments");
    const recentList = document.getElementById("recentDocuments");

    try {
      const payload = await apiRequest("/dashboard");
      const { stats, recentDocuments } = payload;

      welcome.textContent = user.name;

      if (totalDocuments) {
        totalDocuments.textContent = stats.totalDocuments;
      }

      if (identityDocuments) {
        identityDocuments.textContent = stats.identityDocuments;
      }

      if (academicDocuments) {
        academicDocuments.textContent = stats.academicDocuments;
      }

      if (!recentList) {
        return;
      }

      if (!recentDocuments.length) {
        recentList.innerHTML = "<li>No documents added yet. Open the vault and upload your first file.</li>";
        return;
      }

      recentList.innerHTML = recentDocuments
        .map((document) => {
          return `
            <li>
              <strong>${document.title}</strong>
              <span>${document.documentType} - ${document.fileName}</span>
            </li>
          `;
        })
        .join("");
    } catch (error) {
      if (recentList) {
        recentList.innerHTML = `<li>${error.message}</li>`;
      }
    }
  });
}

async function renderDocuments(searchText = "") {
  const user = await requireAuth();
  if (!user) {
    return;
  }

  const totalCount = document.getElementById("documentCount");
  const listContainer = document.getElementById("documentList");
  const typeFilter = document.getElementById("filterDocumentType");
  const sortSelect = document.getElementById("sortDocuments");

  try {
    const queryParams = new URLSearchParams();
    const trimmedSearch = searchText.trim();

    if (trimmedSearch) {
      queryParams.set("search", trimmedSearch);
    }

    if (typeFilter && typeFilter.value) {
      queryParams.set("type", typeFilter.value);
    }

    if (sortSelect && sortSelect.value) {
      queryParams.set("sort", sortSelect.value);
    }

    const query = queryParams.toString() ? `?${queryParams.toString()}` : "";
    const payload = await apiRequest(`/documents${query}`);
    const documents = payload.documents;

    if (totalCount) {
      totalCount.textContent = documents.length;
    }

    if (!listContainer) {
      return;
    }

    if (!documents.length) {
      listContainer.innerHTML = `
        <div class="empty-state">
          <h3>No documents found</h3>
          <p>Try a different search, change the filter, or upload a new file.</p>
        </div>
      `;
      return;
    }

    listContainer.innerHTML = documents
      .map((document) => {
        const previewButton = isImageDocument(document) || isPdfDocument(document)
          ? `<button class="secondary-button" data-preview-id="${document.id}" type="button">Preview</button>`
          : "";
        const safeType = escapeHtml(document.documentType);
        const safeTitle = escapeHtml(document.title);
        const safeFileName = escapeHtml(document.fileName);
        const createdLabel = escapeHtml(formatDateTime(document.createdAt));
        const updatedLabel = escapeHtml(formatDateTime(document.updatedAt));

        return `
          <article class="document-card">
            <div class="document-card__header">
              <div>
                <span class="document-tag">${safeType}</span>
                <h3>${safeTitle}</h3>
                <p>${safeFileName}</p>
              </div>
              <div class="document-card__header-actions">
                <button class="secondary-button" data-edit-id="${document.id}" type="button">Edit</button>
                <button class="danger-button" data-delete-id="${document.id}" type="button">Delete</button>
              </div>
            </div>
            <div class="document-card__meta">
              <span><strong>File:</strong> ${safeFileName}</span>
              <span><strong>Size:</strong> ${formatFileSize(document.fileSize)}</span>
              <span><strong>Added:</strong> ${createdLabel}</span>
              <span><strong>Updated:</strong> ${updatedLabel}</span>
            </div>
            <div class="document-card__actions">
              ${previewButton}
              <a class="download-link" href="${document.fileDataUrl}" download="${safeFileName}">Download</a>
            </div>
          </article>
        `;
      })
      .join("");

    listContainer.querySelectorAll("[data-edit-id]").forEach((button) => {
      button.addEventListener("click", async () => {
        const documentId = button.getAttribute("data-edit-id");
        const document = documents.find((item) => item.id === documentId);

        if (!document) {
          return;
        }

        const nextTitle = window.prompt("Edit document title:", document.title);
        if (nextTitle === null) {
          return;
        }

        const nextType = window.prompt("Edit document type:", document.documentType);
        if (nextType === null) {
          return;
        }

        try {
          await apiRequest(`/documents/${documentId}`, {
            method: "PATCH",
            body: JSON.stringify({
              title: nextTitle.trim(),
              documentType: nextType.trim()
            })
          });
          renderDocuments(searchText);
        } catch (error) {
          window.alert(error.message);
        }
      });
    });

    listContainer.querySelectorAll("[data-delete-id]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await apiRequest(`/documents/${button.getAttribute("data-delete-id")}`, {
            method: "DELETE"
          });
          renderDocuments(searchText);
        } catch (error) {
          window.alert(error.message);
        }
      });
    });

    listContainer.querySelectorAll("[data-preview-id]").forEach((button) => {
      button.addEventListener("click", () => {
        openDocumentPreview(button.getAttribute("data-preview-id"));
      });
    });
  } catch (error) {
    if (listContainer) {
      listContainer.innerHTML = `
        <div class="empty-state">
          <h3>Unable to load documents</h3>
          <p>${error.message}</p>
        </div>
      `;
    }
  }
}

function initDocumentsPage() {
  const form = document.getElementById("documentForm");
  if (!form) {
    return;
  }

  requireAuth().then(async (user) => {
    if (!user) {
      return;
    }

    bindLogoutButtons();

    const searchInput = document.getElementById("searchDocuments");
    const typeFilter = document.getElementById("filterDocumentType");
    const sortSelect = document.getElementById("sortDocuments");
    const message = document.getElementById("documentMessage");
    const ownerName = document.getElementById("documentOwner");

    if (ownerName) {
      ownerName.textContent = user.name;
    }

    renderDocuments();

    if (searchInput) {
      searchInput.addEventListener("input", (event) => {
        renderDocuments(event.target.value);
      });
    }

    if (typeFilter) {
      typeFilter.addEventListener("change", () => {
        renderDocuments(searchInput ? searchInput.value : "");
      });
    }

    if (sortSelect) {
      sortSelect.addEventListener("change", () => {
        renderDocuments(searchInput ? searchInput.value : "");
      });
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const title = document.getElementById("documentTitle").value.trim();
      const documentType = document.getElementById("documentType").value.trim();
      const fileInput = document.getElementById("documentFile");
      const file = fileInput.files[0];

      if (!title || !documentType || !file) {
        showMessage(message, "Title, document type, and file are required.", "error");
        return;
      }

      if (title.length > 120) {
        showMessage(message, "Document title must be 120 characters or fewer.", "error");
        return;
      }

      if (documentType.length > 60) {
        showMessage(message, "Document type must be 60 characters or fewer.", "error");
        return;
      }

      if (file.size > 2 * 1024 * 1024) {
        showMessage(message, "Please upload a file smaller than 2 MB for browser storage.", "error");
        return;
      }

      const normalizedFileType = file.type || "application/octet-stream";
      if (!SUPPORTED_UPLOAD_TYPES.has(normalizedFileType)) {
        showMessage(message, "Only PDF, PNG, JPG, WEBP, and AVIF files are supported.", "error");
        return;
      }

      try {
        const fileDataUrl = await readFileAsDataUrl(file);

        await apiRequest("/documents", {
          method: "POST",
          body: JSON.stringify({
            title,
            documentType,
            fileName: file.name,
            fileSize: file.size,
            fileType: normalizedFileType,
            fileDataUrl
          })
        });

        showMessage(message, "Document stored successfully.", "success");
        form.reset();
        renderDocuments(searchInput ? searchInput.value : "");
      } catch (error) {
        showMessage(message, error.message, "error");
      }
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initLoginPage();
  initSignupPage();
  initWelcomePage();
  initDashboardPage();
  initDocumentsPage();
});
