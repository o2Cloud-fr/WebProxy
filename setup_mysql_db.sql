-- Base de données pour le proxy avec gestion des utilisateurs et rôles
-- Exécuter ces commandes SQL dans votre serveur MySQL pour configurer la base de données

-- Création de la base de données
CREATE DATABASE IF NOT EXISTS vofa2334_domain_proxy;
USE vofa2334_domain_proxy;

-- Table des rôles
CREATE TABLE IF NOT EXISTS roles (
  id INT PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  description VARCHAR(255)
);

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL, -- En production, utilisez un hachage sécurisé pour les mots de passe
  role_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL,
  active BOOLEAN DEFAULT TRUE,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Table des URLs blacklistées
CREATE TABLE IF NOT EXISTS blacklist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url_pattern VARCHAR(255) NOT NULL,
  description VARCHAR(255),
  min_role_id INT,  -- Le rôle minimum requis pour accéder (NULL = bloqué pour tous)
  created_by INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Table des logs d'accès
CREATE TABLE IF NOT EXISTS access_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  url VARCHAR(255) NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status INT,
  blocked BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insertion des rôles par défaut
INSERT INTO roles (id, name, description) VALUES 
(1, 'Admin', 'Accès complet avec droits administratifs'),
(2, 'PowerUser', 'Accès étendu avec quelques restrictions'),
(3, 'User', 'Accès basique avec restrictions');

-- Insertion des utilisateurs par défaut
-- En production, utilisez des mots de passe plus sécurisés et un système de hachage
INSERT INTO users (username, password, role_id) VALUES 
('admin', 'adminpassword', 1),
('poweruser', 'powerpassword', 2),
('user', 'userpassword', 3);

-- Insertion de quelques règles de blacklist par défaut
INSERT INTO blacklist (url_pattern, description, min_role_id, created_by) VALUES 
('facebook.com', 'Réseaux sociaux - accès restreint', 2, 1),
('youtube.com', 'Sites de streaming - accès restreint', 2, 1),
('instagram.com', 'Réseaux sociaux - accès restreint', 2, 1),
('netflix.com', 'Sites de streaming - accès restreint', 2, 1),
('malware.test', 'Site malveillant - bloqué pour tous', NULL, 1);

-- Ajout d'une vue pour simplifier les requêtes de l'interface d'administration
CREATE OR REPLACE VIEW user_permissions AS
SELECT 
  u.id AS user_id,
  u.username,
  r.id AS role_id,
  r.name AS role_name,
  u.active,
  u.last_login
FROM users u
JOIN roles r ON u.role_id = r.id;

-- Ajout d'une vue pour analyser les logs d'accès
CREATE OR REPLACE VIEW access_statistics AS
SELECT 
  u.username,
  a.url,
  COUNT(*) AS access_count,
  SUM(CASE WHEN a.blocked = 1 THEN 1 ELSE 0 END) AS blocked_count,
  MIN(a.timestamp) AS first_access,
  MAX(a.timestamp) AS last_access
FROM access_logs a
LEFT JOIN users u ON a.user_id = u.id
GROUP BY u.username, a.url
ORDER BY access_count DESC;
