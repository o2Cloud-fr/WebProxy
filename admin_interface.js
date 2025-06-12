const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcrypt');

// Configuration de l'interface d'administration
const config = {
  adminPort: 3000,
  mysql: {
    host: '',
    user: '',
    password: '',
    database: ''
  },
  session: {
    secret: 'proxy_admin_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 3600000 } // 1 heure
  },
  roles: {
    ADMIN: 1,
    POWERUSER: 2,
    USER: 3
  }
};

// Créer l'application Express
const app = express();

// Configurer le middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session(config.session));
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Pool de connexions MySQL
let dbPool;

// Middleware pour vérifier l'authentification
const requireLogin = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Middleware pour vérifier le rôle Admin
const requireAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role_id === config.roles.ADMIN) {
    next();
  } else {
    res.status(403).render('error', { 
      message: 'Accès refusé. Droits administrateur requis.',
      user: req.session.user,
      error: null
    });
  }
};

// Initialiser la connexion à la base de données
async function initializeDatabase() {
  try {
    dbPool = await mysql.createPool(config.mysql);
    console.log('Connexion à la base de données établie pour l\'interface d\'administration');
  } catch (err) {
    console.error('Erreur de connexion à la base de données:', err);
    process.exit(1);
  }
}

// Routes pour l'authentification
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [rows] = await dbPool.execute(
      'SELECT id, username, password, role_id FROM users WHERE username = ? AND active = TRUE',
      [username]
    );
    
    if (rows.length === 1) {
      // Dans la version finale, utiliser bcrypt.compare
      // Pour ce POC, comparaison simple
      if (rows[0].password === password) {
        req.session.user = {
          id: rows[0].id,
          username: rows[0].username,
          role_id: rows[0].role_id
        };
        
        // Mettre à jour la date de dernière connexion
        await dbPool.execute(
          'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
          [rows[0].id]
        );
        
        res.redirect('/dashboard');
      } else {
        res.render('login', { error: 'Mot de passe incorrect' });
      }
    } else {
      res.render('login', { error: 'Utilisateur non trouvé ou désactivé' });
    }
  } catch (err) {
    console.error('Erreur de connexion:', err);
    res.render('login', { error: 'Erreur serveur lors de la connexion' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Dashboard principal
app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    // Statistiques utilisateurs
    const [userStats] = await dbPool.execute(
      'SELECT COUNT(*) AS total_users, ' +
      '(SELECT COUNT(*) FROM users WHERE role_id = ?) AS admin_count, ' +
      '(SELECT COUNT(*) FROM users WHERE role_id = ?) AS poweruser_count, ' +
      '(SELECT COUNT(*) FROM users WHERE role_id = ?) AS user_count',
      [config.roles.ADMIN, config.roles.POWERUSER, config.roles.USER]
    );
    
    // Statistiques blacklist - MODIFIED: Check if access_level column exists instead of min_role_id
    const [blacklistStats] = await dbPool.execute(
      'SELECT COUNT(*) AS total_rules, ' +
      'COUNT(CASE WHEN min_role_id IS NULL THEN 1 END) AS total_blocked ' +
      'FROM blacklist'
    );
    
    // Statistiques d'accès récents
    const [recentActivity] = await dbPool.execute(
      'SELECT a.url, a.timestamp, a.blocked, u.username ' +
      'FROM access_logs a ' +
      'JOIN users u ON a.user_id = u.id ' +
      'ORDER BY a.timestamp DESC LIMIT 10'
    );
    
    // Top sites bloqués
    const [topBlocked] = await dbPool.execute(
      'SELECT url, COUNT(*) AS block_count ' +
      'FROM access_logs ' +
      'WHERE blocked = TRUE ' +
      'GROUP BY url ' +
      'ORDER BY block_count DESC ' +
      'LIMIT 5'
    );
    
    res.render('dashboard', {
      user: req.session.user,
      userStats: userStats[0],
      blacklistStats: blacklistStats[0],
      recentActivity,
      topBlocked
    });
  } catch (err) {
    console.error('Erreur lors du chargement du tableau de bord:', err);
    res.render('error', { 
      message: 'Erreur lors du chargement du tableau de bord: ' + err.message, 
      user: req.session.user,
      error: err 
    });
  }
});

// Gestion des utilisateurs
app.get('/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [users] = await dbPool.execute(
      'SELECT u.id, u.username, u.active, u.last_login, r.name AS role_name, r.id AS role_id ' +
      'FROM users u JOIN roles r ON u.role_id = r.id ' +
      'ORDER BY u.username'
    );
    
    const [roles] = await dbPool.execute('SELECT id, name FROM roles ORDER BY id');
    
    res.render('users', {
      user: req.session.user,
      users,
      roles,
      message: req.query.message
    });
  } catch (err) {
    console.error('Erreur lors du chargement des utilisateurs:', err);
    res.render('error', { 
      message: 'Erreur lors du chargement des utilisateurs', 
      user: req.session.user,
      error: err
    });
  }
});

app.post('/users/add', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { username, password, role_id, active } = req.body;
    const isActive = active === 'on' ? 1 : 0;
    
    // Dans une version de production, hasher le mot de passe
    // const hashedPassword = await bcrypt.hash(password, 10);
    
    await dbPool.execute(
      'INSERT INTO users (username, password, role_id, active) VALUES (?, ?, ?, ?)',
      [username, password, role_id, isActive]
    );
    
    res.redirect('/users?message=Utilisateur ajouté avec succès');
  } catch (err) {
    console.error('Erreur lors de l\'ajout d\'un utilisateur:', err);
    res.redirect('/users?message=Erreur: ' + err.message);
  }
});

app.post('/users/edit/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { username, password, role_id, active } = req.body;
    const isActive = active === 'on' ? 1 : 0;
    
    if (password && password.trim() !== '') {
      // Mise à jour avec nouveau mot de passe
      await dbPool.execute(
        'UPDATE users SET username = ?, password = ?, role_id = ?, active = ? WHERE id = ?',
        [username, password, role_id, isActive, userId]
      );
    } else {
      // Mise à jour sans changer le mot de passe
      await dbPool.execute(
        'UPDATE users SET username = ?, role_id = ?, active = ? WHERE id = ?',
        [username, role_id, isActive, userId]
      );
    }
    
    res.redirect('/users?message=Utilisateur mis à jour avec succès');
  } catch (err) {
    console.error('Erreur lors de la mise à jour d\'un utilisateur:', err);
    res.redirect('/users?message=Erreur: ' + err.message);
  }
});

app.get('/users/delete/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Vérifier que l'utilisateur n'est pas en train de se supprimer lui-même
    if (parseInt(userId) === req.session.user.id) {
      return res.redirect('/users?message=Vous ne pouvez pas supprimer votre propre compte');
    }
    
    // Supprimer d'abord les entrées liées dans les logs
    await dbPool.execute('DELETE FROM access_logs WHERE user_id = ?', [userId]);
    
    // Puis supprimer l'utilisateur
    await dbPool.execute('DELETE FROM users WHERE id = ?', [userId]);
    
    res.redirect('/users?message=Utilisateur supprimé avec succès');
  } catch (err) {
    console.error('Erreur lors de la suppression d\'un utilisateur:', err);
    res.redirect('/users?message=Erreur: ' + err.message);
  }
});

// Gestion de la blacklist
app.get('/blacklist', requireLogin, async (req, res) => {
  try {
    // MODIFIED: Updated to use access_level instead of min_role_id
const [blacklistEntries] = await dbPool.execute(
  `SELECT b.id, b.url_pattern, b.description, b.min_role_id, r.name AS min_role_name, 
  u.username AS created_by_user 
  FROM blacklist b 
  LEFT JOIN roles r ON b.min_role_id = r.id 
  LEFT JOIN users u ON b.created_by = u.id 
  ORDER BY b.url_pattern`
);
    
    const [roles] = await dbPool.execute('SELECT id, name FROM roles ORDER BY id');
    
    res.render('blacklist', {
      user: req.session.user,
      blacklistEntries,
      roles,
      message: req.query.message
    });
  } catch (err) {
    console.error('Erreur lors du chargement de la blacklist:', err);
    res.render('error', { 
      message: 'Erreur lors du chargement de la blacklist', 
      user: req.session.user,
      error: err
    });
  }
});

app.post('/blacklist/add', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { url_pattern, description, min_role_id } = req.body;

    const cleanValue = (val) => val === undefined ? null : val;
    const roleId = cleanValue(min_role_id === 'null' ? null : min_role_id);
    const cleanUrlPattern = cleanValue(url_pattern);
    const cleanDescription = cleanValue(description);

    // Vérification simple pour éviter d'ajouter une règle vide
    if (!cleanUrlPattern) {
      return res.redirect('/blacklist?message=Erreur: Le champ "URL pattern" est obligatoire');
    }

    await dbPool.execute(
      'INSERT INTO blacklist (url_pattern, description, min_role_id, created_by) VALUES (?, ?, ?, ?)',
      [cleanUrlPattern, cleanDescription, roleId, req.session.user.id]
    );

    res.redirect('/blacklist?message=Règle ajoutée avec succès');
  } catch (err) {
    console.error('Erreur lors de l\'ajout d\'une règle blacklist:', err);
    res.redirect('/blacklist?message=Erreur: ' + err.message);
  }
});




app.post('/blacklist/edit/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    // Correction: Utiliser min_role_id au lieu de min_role_id
    const ruleId = req.params.id;
    const { url_pattern, description, min_role_id } = req.body;
    const roleId = min_role_id === 'null' ? null : min_role_id;
   
    await dbPool.execute(
      'UPDATE blacklist SET url_pattern = ?, description = ?, min_role_id = ? WHERE id = ?',
      [url_pattern, description, roleId, ruleId]
    );
   
    res.redirect('/blacklist?message=Règle mise à jour avec succès');
  } catch (err) {
    console.error('Erreur lors de la mise à jour d\'une règle blacklist:', err);
    res.redirect('/blacklist?message=Erreur: ' + err.message);
  }
});

app.get('/blacklist/delete/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const ruleId = req.params.id;
    
    await dbPool.execute('DELETE FROM blacklist WHERE id = ?', [ruleId]);
    
    res.redirect('/blacklist?message=Règle supprimée avec succès');
  } catch (err) {
    console.error('Erreur lors de la suppression d\'une règle blacklist:', err);
    res.redirect('/blacklist?message=Erreur: ' + err.message);
  }
});

// Logs d'accès
app.get('/logs', requireLogin, requireAdmin, async (req, res) => {
  try {
    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;
    
    // Filtres
    const username = req.query.username || '';
    const url = req.query.url || '';
    const blockedOnly = req.query.blocked === 'true';
    
    // Construction de la requête SQL avec filtres
    let query = 'SELECT a.id, a.url, a.timestamp, a.status, a.blocked, u.username ' +
                'FROM access_logs a ' +
                'LEFT JOIN users u ON a.user_id = u.id WHERE 1=1';
    
    const params = [];
    
    if (username) {
      query += ' AND u.username LIKE ?';
      params.push(`%${username}%`);
    }
    
    if (url) {
      query += ' AND a.url LIKE ?';
      params.push(`%${url}%`);
    }
    
    if (blockedOnly) {
      query += ' AND a.blocked = TRUE';
    }
    
    // Compter le nombre total d'enregistrements (pour pagination)
    const [countResult] = await dbPool.execute(`SELECT COUNT(*) as total FROM (${query}) as filtered_count`, params);
    const totalLogs = countResult[0].total;
    const totalPages = Math.ceil(totalLogs / limit);
    
    // Récupérer les logs avec pagination
    query += ' ORDER BY a.timestamp DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const [logs] = await dbPool.execute(query, params);
    
    res.render('logs', {
      user: req.session.user,
      logs,
      currentPage: page,
      totalPages,
      username,
      url,
      blockedOnly
    });
  } catch (err) {
    console.error('Erreur lors du chargement des logs:', err);
    res.render('error', { 
      message: 'Erreur lors du chargement des logs', 
      user: req.session.user,
      error: err 
    });
  }
});

// Profil utilisateur (tous les utilisateurs peuvent accéder à leur propre profil)
app.get('/profile', requireLogin, async (req, res) => {
  try {
    const [userInfo] = await dbPool.execute(
      'SELECT u.id, u.username, u.created_at, u.last_login, r.name AS role_name ' +
      'FROM users u JOIN roles r ON u.role_id = r.id ' +
      'WHERE u.id = ?',
      [req.session.user.id]
    );
    
    res.render('profile', {
      user: req.session.user,
      userInfo: userInfo[0],
      message: req.query.message
    });
  } catch (err) {
    console.error('Erreur lors du chargement du profil:', err);
    res.render('error', { 
      message: 'Erreur lors du chargement du profil', 
      user: req.session.user,
      error: err
    });
  }
});

app.post('/profile/update-password', requireLogin, async (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    
    // Vérifier que les deux nouveaux mots de passe correspondent
    if (new_password !== confirm_password) {
      return res.redirect('/profile?message=Les nouveaux mots de passe ne correspondent pas');
    }
    
    // Récupérer le mot de passe actuel de l'utilisateur
    const [userRows] = await dbPool.execute(
      'SELECT password FROM users WHERE id = ?',
      [req.session.user.id]
    );
    
    if (userRows.length === 0) {
      return res.redirect('/profile?message=Erreur: Utilisateur non trouvé');
    }
    
    // Vérifier que le mot de passe actuel est correct
    // Dans une version de production, utiliser bcrypt.compare
    if (userRows[0].password !== current_password) {
      return res.redirect('/profile?message=Le mot de passe actuel est incorrect');
    }
    
    // Mettre à jour le mot de passe
    // Dans une version de production, hasher le mot de passe
    // const hashedPassword = await bcrypt.hash(new_password, 10);
    
    await dbPool.execute(
      'UPDATE users SET password = ? WHERE id = ?',
      [new_password, req.session.user.id]
    );
    
    res.redirect('/profile?message=Mot de passe mis à jour avec succès');
  } catch (err) {
    console.error('Erreur lors de la mise à jour du mot de passe:', err);
    res.redirect('/profile?message=Erreur: ' + err.message);
  }
});

// Rapports et statistiques
app.get('/stats', requireLogin, requireAdmin, async (req, res) => {
  try {
    const period = req.query.period || '30days';

    let dateCondition = '';
    switch (period) {
      case '7days':
        dateCondition = "WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
        break;
      case '30days':
        dateCondition = "WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
        break;
      case '90days':
        dateCondition = "WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 90 DAY)";
        break;
      case 'all':
      default:
        dateCondition = '';
    }

    const [dailyStats] = await dbPool.execute(`
      SELECT 
        DATE(timestamp) AS date, 
        COUNT(*) AS total_requests,
        SUM(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) AS blocked_requests
      FROM access_logs
      ${dateCondition}
      GROUP BY DATE(timestamp)
      ORDER BY date
    `);

    // Gestion du cas où aucune donnée n'est disponible
if (dailyStats.length === 0) {
  // Générer des données fictives pour éviter les erreurs de graphique vide
  const currentDate = new Date();
  for (let i = 0; i < 7; i++) {
    const date = new Date(currentDate);
    date.setDate(date.getDate() - i);
    dailyStats.push({
      date: date.toISOString().split('T')[0],
      total_requests: 0,
      blocked_requests: 0
    });
  }
  // Inverser pour avoir l'ordre chronologique
  dailyStats.reverse();
}

    const [topUsers] = await dbPool.execute(`
      SELECT 
        u.username, 
        COUNT(*) AS requests,
        SUM(CASE WHEN a.blocked = TRUE THEN 1 ELSE 0 END) AS blocked
      FROM access_logs a
      JOIN users u ON a.user_id = u.id
      ${dateCondition}
      GROUP BY u.username
      ORDER BY requests DESC
      LIMIT 10
    `);

    const [topSitesRaw] = await dbPool.execute(`
      SELECT 
        url, 
        COUNT(*) AS visits,
        SUM(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) AS blocked_count,
        SUM(CASE WHEN blocked = FALSE THEN 1 ELSE 0 END) AS allowed_count
      FROM access_logs
      ${dateCondition}
      GROUP BY url
      ORDER BY visits DESC
      LIMIT 10
    `);

    // Calcul de allowed pour l'affichage
    const topSites = topSitesRaw.map(site => ({
      url: site.url,
      visits: site.visits,
      // Un site est considéré comme autorisé si la majorité des requêtes sont autorisées
      allowed: site.allowed_count > site.blocked_count
    }));

    const [hourlyDistribution] = await dbPool.execute(`
      SELECT 
        HOUR(timestamp) AS hour, 
        COUNT(*) AS request_count
      FROM access_logs
      ${dateCondition}
      GROUP BY hour
      ORDER BY hour
    `);
    

    res.render('stats', {
      user: req.session.user,
      period,
      dailyStats,
      topUsers,
      topSites,
      hourlyDistribution
    });

  } catch (error) {
    console.error('Erreur statistiques:', error);
    res.render('error', { 
      message: "Erreur lors du chargement des statistiques", 
      error,
      user: req.session.user,
      period: '30days'
    });
  }
});




// Page d'erreur
app.use((req, res) => {
  res.status(404).render('error', { 
    message: 'Page non trouvée', 
    user: req.session.user,
    error: null
  });
});

// Démarrer le serveur
async function startAdminServer() {
  try {
    await initializeDatabase();
    
    app.listen(config.adminPort, () => {
      console.log(`Interface d'administration démarrée sur le port ${config.adminPort}`);
      console.log(`Accès: http://localhost:${config.adminPort}`);
    });
  } catch (err) {
    console.error('Erreur lors du démarrage du serveur d\'administration:', err);
    process.exit(1);
  }
}

// Lancer le serveur
startAdminServer();