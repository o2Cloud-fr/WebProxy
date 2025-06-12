const http = require('http');
const https = require('https');
const net = require('net');
const url = require('url');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise'); // Utilisation de mysql2 avec support des promesses

// Configuration du proxy
const config = {
  host: '0.0.0.0',
  port: 8080,
  wpadPort: 80,  // Port pour le serveur WPAD (typiquement 80)
  mysql: {
    host: '',
    user: '',
    password: '',
    database: ''
  },
  authentication: true,
  // Les identifiants sont maintenant stockés dans MySQL
  roles: {
    ADMIN: 1,     // Accès complet
    POWERUSER: 2, // Peut accéder à plus de sites mais avec certaines restrictions
    USER: 3       // Accès basique avec plusieurs restrictions
  }
};

// Page HTML à afficher lorsqu'une URL est bloquée
const blockedPageHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Accès Refusé</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
            color: #333;
            text-align: center;
        }
        .container {
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #d9534f;
        }
        .icon {
            font-size: 60px;
            margin-bottom: 20px;
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⛔</div>
        <h1>Accès Refusé</h1>
        <p>Cette URL a été bloquée par l'administrateur système.</p>
        <p>Si vous pensez qu'il s'agit d'une erreur, veuillez contacter votre administrateur.</p>
        <p><small>Proxy Service</small></p>
    </div>
</body>
</html>
`;

// Pool de connexions MySQL
let dbPool;

// Initialisation de la base de données MySQL
async function initializeDatabase() {
  try {
    dbPool = await mysql.createPool(config.mysql);
    
    // Vérifier si les tables existent, sinon les créer
    await dbPool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        active BOOLEAN DEFAULT TRUE
      )
    `);
    
    await dbPool.execute(`
      CREATE TABLE IF NOT EXISTS roles (
        id INT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        description VARCHAR(255)
      )
    `);
    
    await dbPool.execute(`
      CREATE TABLE IF NOT EXISTS blacklist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url_pattern VARCHAR(255) NOT NULL,
        description VARCHAR(255),
        min_role_id INT,  -- Le rôle minimum requis pour accéder (NULL = bloqué pour tous)
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
      )
    `);
    
    await dbPool.execute(`
      CREATE TABLE IF NOT EXISTS access_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        url VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status INT,
        blocked BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    // Insérer les rôles par défaut s'ils n'existent pas
    const [roles] = await dbPool.execute('SELECT * FROM roles');
    if (roles.length === 0) {
      await dbPool.execute('INSERT INTO roles (id, name, description) VALUES (?, ?, ?)', 
        [config.roles.ADMIN, 'Admin', 'Accès complet avec droits administratifs']);
      await dbPool.execute('INSERT INTO roles (id, name, description) VALUES (?, ?, ?)', 
        [config.roles.POWERUSER, 'PowerUser', 'Accès étendu avec quelques restrictions']);
      await dbPool.execute('INSERT INTO roles (id, name, description) VALUES (?, ?, ?)', 
        [config.roles.USER, 'User', 'Accès basique avec restrictions']);
      
      console.log('Rôles par défaut créés avec succès');
    }
    
    // Créer un utilisateur admin par défaut si aucun n'existe
    const [users] = await dbPool.execute('SELECT * FROM users');
    if (users.length === 0) {
      // NOTE: Dans un environnement de production, utiliser un hachage sécurisé pour les mots de passe
      await dbPool.execute('INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)', 
        ['admin', 'adminpassword', config.roles.ADMIN]);
      await dbPool.execute('INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)', 
        ['poweruser', 'powerpassword', config.roles.POWERUSER]);
      await dbPool.execute('INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)', 
        ['user', 'userpassword', config.roles.USER]);
      
      console.log('Utilisateurs par défaut créés avec succès');
    }
    
    // Ajouter quelques URL blacklistées par défaut
    const [blacklists] = await dbPool.execute('SELECT * FROM blacklist');
    if (blacklists.length === 0) {
      await dbPool.execute('INSERT INTO blacklist (url_pattern, description, min_role_id) VALUES (?, ?, ?)', 
        ['facebook.com', 'Réseaux sociaux - accès restreint', config.roles.POWERUSER]);
      await dbPool.execute('INSERT INTO blacklist (url_pattern, description, min_role_id) VALUES (?, ?, ?)', 
        ['youtube.com', 'Sites de streaming - accès restreint', config.roles.POWERUSER]);
      await dbPool.execute('INSERT INTO blacklist (url_pattern, description, min_role_id) VALUES (?, ?, ?)', 
        ['malware.test', 'Site malveillant - bloqué pour tous', null]);
      
      console.log('Règles de blacklist par défaut créées avec succès');
    }
    
    console.log('Base de données initialisée avec succès');
  } catch (err) {
    console.error('Erreur lors de l\'initialisation de la base de données:', err);
    process.exit(1);
  }
}

// Fonction pour vérifier l'authentification via MySQL
async function authenticateUser(authHeader) {
  if (!config.authentication) {
    return { authenticated: true, role: config.roles.ADMIN, userId: null };
  }
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { authenticated: false };
  }
  
  try {
    // Extraire et décoder le header Basic Auth
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');
    
    // Vérifier les identifiants dans la base de données
    const [rows] = await dbPool.execute(
      'SELECT id, username, role_id FROM users WHERE username = ? AND password = ? AND active = TRUE',
      [username, password]
    );
    
    if (rows.length === 1) {
      // Mettre à jour la date de dernière connexion
      await dbPool.execute(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
        [rows[0].id]
      );
      
      return { 
        authenticated: true, 
        userId: rows[0].id,
        username: rows[0].username,
        role: rows[0].role_id
      };
    }
    
    return { authenticated: false };
  } catch (err) {
    console.error('Erreur d\'authentification:', err);
    return { authenticated: false };
  }
}

// Fonction pour vérifier si une URL est blacklistée
async function checkUrlAccess(url, userRole) {
  try {
    // Si userRole est undefined (utilisateur non authentifié), le considérer comme un USER
    const effectiveRole = userRole || config.roles.USER;
    
    // Récupérer toutes les règles de blacklist qui correspondent à cette URL
    const [rows] = await dbPool.execute(
      'SELECT url_pattern, min_role_id FROM blacklist'
    );
    
    // Vérifier si l'URL correspond à l'un des patterns blacklistés
    for (const rule of rows) {
      if (url.includes(rule.url_pattern)) {
        // Si min_role_id est NULL, l'URL est bloquée pour tous
        if (rule.min_role_id === null) {
          return { allowed: false };
        }
        
        // Vérifier si l'utilisateur a un rôle suffisant pour accéder à cette URL
        // Plus petit le numéro de rôle, plus élevés sont les privilèges
        if (effectiveRole > rule.min_role_id) {
          return { allowed: false };
        }
      }
    }
    
    return { allowed: true };
  } catch (err) {
    console.error('Erreur lors de la vérification des règles d\'accès:', err);
    // En cas d'erreur, autoriser par défaut (politique permissive)
    return { allowed: true };
  }
}

// Fonction pour journaliser les accès
async function logAccess(userId, requestUrl, status, blocked) {
  try {
    await dbPool.execute(
      'INSERT INTO access_logs (user_id, url, status, blocked) VALUES (?, ?, ?, ?)',
      [userId, requestUrl, status, blocked]
    );
  } catch (err) {
    console.error('Erreur lors de la journalisation de l\'accès:', err);
  }
}

// Fonction pour demander une authentification
function requestAuthentication(res) {
  res.writeHead(407, {
    'Proxy-Authenticate': 'Basic realm="Proxy Authentication Required"',
    'Content-Type': 'text/plain'
  });
  res.end('Proxy authentication required');
}

// Fonction pour servir la page bloquée
function serveBlockedPage(res) {
  res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(blockedPageHTML);
}

// Fonction pour générer dynamiquement le fichier PAC
function generatePacFile(proxyHost, proxyPort) {
  return `function FindProxyForURL(url, host) {
    // Ne pas utiliser de proxy pour les adresses locales
    if (isPlainHostName(host) ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    
    // Utiliser le proxy pour tout le reste
    return "PROXY ${proxyHost}:${proxyPort}";
}`;
}

// Créer le serveur proxy HTTP
const createProxyServer = async () => {
  const proxyServer = http.createServer(async (req, res) => {
    // Vérifier l'authentification
    const authHeader = req.headers['proxy-authorization'];
    const auth = await authenticateUser(authHeader);
    
    if (!auth.authenticated) {
      requestAuthentication(res);
      return;
    }
    
    console.log(`Requête HTTP: ${req.method} ${req.url} - Utilisateur: ${auth.username || 'Non authentifié'}`);
    
    // Extraire les informations sur la cible
    const parsedUrl = url.parse(req.url);
    
    // Vérifier si l'URL est autorisée
    const accessCheck = await checkUrlAccess(req.url, auth.role);
    if (!accessCheck.allowed) {
      console.log(`Accès bloqué à ${req.url} pour l'utilisateur ${auth.username || 'Non authentifié'}`);
      await logAccess(auth.userId, req.url, 403, true);
      serveBlockedPage(res);
      return;
    }
    
    // Supprimer les en-têtes spécifiques au proxy
    delete req.headers['proxy-authorization'];
    delete req.headers['proxy-connection'];
    
    // Options pour la requête cible
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.path,
      method: req.method,
      headers: req.headers
    };
    
    // Créer la requête vers le serveur cible
    const proxyReq = http.request(options, (proxyRes) => {
      // Journaliser l'accès réussi
      logAccess(auth.userId, req.url, proxyRes.statusCode, false);
      
      // Copier les en-têtes de réponse
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      
      // Transférer les données de réponse
      proxyRes.pipe(res);
    });
    
    // Gestion des erreurs
    proxyReq.on('error', (err) => {
      console.error(`Erreur de requête: ${err.message}`);
      logAccess(auth.userId, req.url, 500, false);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`Erreur de connexion: ${err.message}`);
    });
    
    // Transférer les données de la requête
    req.pipe(proxyReq);
  });

  // Gérer la méthode CONNECT pour HTTPS
  proxyServer.on('connect', async (req, clientSocket, head) => {
    // Vérifier l'authentification pour CONNECT
    const authHeader = req.headers['proxy-authorization'];
    const auth = await authenticateUser(authHeader);
    
    if (!auth.authenticated) {
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\n' +
                        'Proxy-Authenticate: Basic realm="Proxy Authentication Required"\r\n' +
                        '\r\n');
      clientSocket.end();
      return;
    }
    
    
    // Extraire le nom d'hôte et le port
    const [hostname, port] = req.url.split(':');
    const targetPort = parseInt(port) || 443;
    
    console.log(`Requête CONNECT: ${hostname}:${targetPort} - Utilisateur: ${auth.username || 'Non authentifié'}`);
    
    // Vérifier si l'URL est autorisée
    const accessCheck = await checkUrlAccess(hostname, auth.role);
    if (!accessCheck.allowed) {
      console.log(`Accès HTTPS bloqué à ${hostname} pour l'utilisateur ${auth.username || 'Non authentifié'}`);
      await logAccess(auth.userId, hostname, 403, true);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n' +
                        'Content-Type: text/html\r\n' +
                        '\r\n');
      clientSocket.write(blockedPageHTML);
      clientSocket.end();
      return;
    }
    
    // Créer une connexion au serveur cible
    const targetSocket = net.connect(targetPort, hostname, () => {
      // Connexion établie avec succès
      logAccess(auth.userId, hostname, 200, false);
      
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
                        'Connection: keep-alive\r\n' +
                        '\r\n');
      
      // Envoyer les données en attente si présentes
      if (head.length > 0) {
        targetSocket.write(head);
      }
      
      // Mettre en place le tunnel
      clientSocket.pipe(targetSocket);
      targetSocket.pipe(clientSocket);
    });
    
    // Gestion des erreurs
    targetSocket.on('error', (err) => {
      console.error(`Erreur de connexion HTTPS: ${err.message}`);
      logAccess(auth.userId, hostname, 500, false);
      clientSocket.end();
    });
    
    clientSocket.on('error', (err) => {
      console.error(`Erreur de socket client: ${err.message}`);
      targetSocket.end();
    });
    
    // Nettoyer les connexions lorsqu'elles sont fermées
    clientSocket.on('close', () => {
      if (!targetSocket.destroyed) {
        targetSocket.end();
      }
    });
    
    targetSocket.on('close', () => {
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });
  });

  return proxyServer;
};

// Créer le serveur WPAD pour servir le fichier PAC
const wpadServer = http.createServer((req, res) => {
  const pathname = url.parse(req.url).pathname;
  console.log(`Requête WPAD: ${req.method} ${req.url}`);
  
  // Servir le fichier PAC sur les chemins standards
  if (pathname === '/wpad.dat' || pathname === '/proxy.pac') {
    // Déterminer automatiquement l'adresse IP du serveur
    const interfaces = require('os').networkInterfaces();
    let serverIp = '127.0.0.1'; // Par défaut
    
    // Essayer de trouver une adresse IP non interne
    Object.keys(interfaces).forEach((ifname) => {
      interfaces[ifname].forEach((iface) => {
        if (iface.family === 'IPv4' && !iface.internal) {
          serverIp = iface.address;
        }
      });
    });
    
    const pacContent = generatePacFile(serverIp, config.port);
    
    res.writeHead(200, {
      'Content-Type': 'application/x-ns-proxy-autoconfig',
      'Content-Length': Buffer.byteLength(pacContent)
    });
    res.end(pacContent);
    return;
  }
  
  // Pour toutes les autres requêtes, retourner 404
  res.writeHead(404, {'Content-Type': 'text/plain'});
  res.end('Not Found');
});

// Démarrer l'application
async function startApp() {
  try {
    // Initialiser la base de données
    await initializeDatabase();
    
    // Créer et démarrer le serveur proxy
    const proxyServer = await createProxyServer();
    proxyServer.listen(config.port, config.host, () => {
      console.log(`Proxy HTTP/HTTPS démarré sur ${config.host}:${config.port}`);
      console.log(`Authentification: ${config.authentication ? 'Activée via MySQL' : 'Désactivée'}`);
    });

    // Démarrer le serveur WPAD
    wpadServer.listen(config.wpadPort, config.host, () => {
      console.log(`Serveur WPAD démarré sur ${config.host}:${config.wpadPort}`);
      console.log(`Fichier PAC disponible sur http://<votre-ip>/wpad.dat et http://<votre-ip>/proxy.pac`);
    });

    // Gestion des erreurs des serveurs
    proxyServer.on('error', (err) => {
      console.error('Erreur du serveur proxy:', err.message);
    });

    wpadServer.on('error', (err) => {
      console.error('Erreur du serveur WPAD:', err.message);
      console.log('Note: Le port 80 nécessite des privilèges root/administrateur.');
      console.log('Vous pouvez modifier config.wpadPort si nécessaire.');
    });

  } catch (err) {
    console.error('Erreur lors du démarrage de l\'application:', err);
    process.exit(1);
  }
}

// Appel pour démarrer l'application
startApp();

// Afficher des instructions pour la configuration DNS/DHCP
console.log('\nInstructions pour la configuration WPAD complète:');
console.log('1. Configurer votre serveur DNS pour résoudre "wpad" vers l\'adresse IP de ce serveur');
console.log('   OU configurer votre serveur DHCP pour fournir l\'option 252 avec la valeur "http://wpad/wpad.dat"');
console.log('2. Les clients découvriront automatiquement le proxy et utiliseront le fichier de configuration PAC');
console.log('\nUtilisateurs par défaut:');
console.log('- Admin: admin/adminpassword');
console.log('- PowerUser: poweruser/powerpassword');
console.log('- User: user/userpassword');
