# 🔒 AD Log Analyzer

> Application locale pour analyser les logs Active Directory — **sans AD Audit, sans agent, sans coût.**

[![GitHub](https://img.shields.io/badge/GitHub-Jecamara%2FAD__audit__local-181717?style=flat&logo=github)](https://github.com/Jecamara/AD_audit_local)

Toutes les données restent sur votre machine. Aucune information n'est envoyée sur internet.

---

## 📦 Contenu du repository

| Fichier | Description |
|---|---|
| `ad-log-analyzer.html` | Application web locale (ouvrir dans Chrome/Edge) |
| `Export-ADLogs.ps1` | Script PowerShell pour convertir les `.evtx` en CSV |

---

## 📥 Installation

```bash
git clone https://github.com/Jecamara/AD_audit_local.git
cd AD_audit_local
```

Ou téléchargez directement les fichiers depuis la page GitHub.

---

## 🚀 Démarrage rapide

### 1. Exporter vos logs depuis Windows

Ouvrez **PowerShell en tant qu'Administrateur** et exécutez :

```powershell
# Export depuis le journal Security live (le plus courant)
.\Export-ADLogs.ps1

# Depuis un fichier .evtx spécifique
.\Export-ADLogs.ps1 -Source "C:\Windows\System32\winevt\Logs\Security.evtx"

# Avec filtre de dates et volume personnalisé
.\Export-ADLogs.ps1 -StartTime "2025-01-01" -MaxEvents 20000

# Export en JSON
.\Export-ADLogs.ps1 -Format JSON
```

Le script génère un fichier `.csv` sur votre Bureau.

### 2. Analyser dans l'application

1. Ouvrez `ad-log-analyzer.html` dans **Chrome ou Edge**
2. Glissez-déposez le `.csv` généré dans la zone d'import
3. Naviguez entre les onglets : Dashboard, Événements, Alertes, Export

> 💡 **Sans logs ?** Cliquez sur *"Charger des données de démonstration"* pour tester avec 280+ événements synthétiques incluant des anomalies injectées.

---

## 🎯 Fonctionnalités

### 📊 Dashboard
- Compteurs clés : total événements, échecs auth (4625), comptes modifiés, connexions OK
- Timeline d'activité sur la période
- Top EventIDs, top utilisateurs en échec, top machines

### 📋 Événements
- Table complète avec pagination (50 par page)
- **Recherche** sur tous les champs (utilisateur, EventID, machine, message)
- **Filtres** : EventID, sévérité (critique / avertissement / info), utilisateur
- Tri sur toutes les colonnes

### 🚨 Alertes automatiques
Détection sans configuration de :

| Alerte | EventID | Seuil |
|---|---|---|
| Brute force possible | 4625 | ≥ 5 échecs par compte |
| Compte verrouillé | 4740 | ≥ 1 |
| Escalade de privilèges | 4732 | ≥ 1 (ajout aux Administrators) |
| Service suspect installé | 7045 | ≥ 1 |
| Suppression de compte | 4726 | ≥ 1 |
| Échecs Kerberos répétés | 4771 | ≥ 3 |

**Règles personnalisées** : ajoutez vos propres seuils directement dans l'onglet Export.

### 💾 Export
- **CSV** compatible Excel (séparateur `;`)
- **JSON** structuré pour traitement automatisé
- **Rapport HTML** complet avec alertes et tableau des 100 premiers événements

---

## 📋 EventIDs surveillés

### Connexions / Authentification
| EventID | Description |
|---|---|
| 4624 | Connexion réussie |
| 4625 | Échec de connexion |
| 4634 | Déconnexion |
| 4648 | Connexion avec credentials explicites |
| 4768 / 4769 | Tickets Kerberos (TGT / service) |
| 4771 | Échec pré-authentification Kerberos |
| 4776 | Authentification NTLM sur DC |

### Gestion des comptes
| EventID | Description |
|---|---|
| 4720 | Compte créé |
| 4722 / 4725 | Compte activé / désactivé |
| 4723 / 4724 | Changement / réinitialisation mot de passe |
| 4726 | Compte supprimé |
| 4738 | Compte modifié |
| 4740 | Compte verrouillé |

### Groupes de sécurité
| EventID | Description |
|---|---|
| 4728 / 4729 | Ajout / retrait groupe sécurité global |
| 4732 / 4733 | Ajout / retrait groupe Administrators |
| 4756 | Ajout groupe universel |

### Accès aux objets
| EventID | Description |
|---|---|
| 4660 | Objet supprimé |
| 4663 | Accès objet tenté |
| 5140 / 5145 | Accès partage réseau |

### Système
| EventID | Description |
|---|---|
| 4946 | Règle pare-feu ajoutée |
| 7045 | Service système installé |

---

## 📁 Formats d'import supportés

| Format | Notes |
|---|---|
| `.csv` | Export PowerShell `Export-Csv` ou Observateur d'événements Windows |
| `.json` | Tableau d'objets ou export `ConvertTo-Json` |
| `.xml` | Export XML Windows Event Log |
| `.txt` | Logs bruts — parsing basique |
| `.evtx` | ⚠️ Binaire — utiliser `Export-ADLogs.ps1` pour convertir d'abord |

---

## ⚙️ Prérequis

- **PowerShell 5.1+** (inclus dans Windows 10/11) pour le script d'export
- **Chrome, Edge ou Firefox** récent pour l'application HTML
- **Droits Administrateur** pour lire le journal Security

---

## 🔐 Confidentialité

L'application fonctionne **entièrement hors ligne** :
- Aucun serveur backend
- Aucune dépendance externe (PapaParse est chargé depuis cdnjs.cloudflare.com uniquement pour le parsing CSV)
- Aucune donnée transmise
- Les logs ne quittent jamais votre navigateur

---

## 📝 Licence

MIT — libre d'utilisation, modification et distribution.
