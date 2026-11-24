function privacyPage(email) {
  const address = typeof email === 'string' ? email.trim() : '';
  const contact = /^[a-z0-9._+%-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(address)
    ? '<a href="mailto:' + encodeURIComponent(address).replace('%40', '@') + '">' + address + '</a>'
    : 'la messagerie privée de votre espace de cours, à l’attention de l’équipe Rempart';

  return '<!doctype html>' + [
    '<html lang="fr"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>Confidentialité · Rempart</title>',
    '<style>',
    'body{margin:0;background:#0f1222;color:#e8e8f0;font:16px/1.6 system-ui,sans-serif}',
    'main{max-width:48rem;margin:auto;padding:2rem 1.25rem 3rem}',
    'h1,h2{line-height:1.2}h2{margin-top:2rem}a{color:#ffae82}',
    'dl{padding:1rem 1.25rem;background:#1b2040;border-radius:.5rem}',
    'dt{font-weight:700}dd{margin:.2rem 0 1rem}dd:last-child{margin-bottom:0}',
    '</style></head><body><main>',
    '<p><a href="/">← Accueil</a></p>',
    '<h1>Confidentialité</h1>',
    '<p>Cette page décrit l’usage des données de l’instance pédagogique locale de Rempart.</p>',
    '<h2>Finalités et bases légales</h2>',
    '<dl>',
    '<dt>Créer votre compte et fournir les fonctions demandées</dt>',
    '<dd>Adresse électronique, mot de passe haché, notes et fichiers déposés. Le traitement sert à fournir le service demandé (exécution du service, article 6.1.b du RGPD).</dd>',
    '<dt>Protéger le compte et diagnostiquer les incidents</dt>',
    '<dd>Cookies de session et anti-CSRF, compteurs de tentatives par compte et adresse IP, journaux techniques et double authentification facultative. La base est l’intérêt légitime à protéger les accès et le service (article 6.1.f du RGPD). Le secret TOTP est chiffré au repos et les codes de secours sont hachés.</dd>',
    '</dl>',
    '<h2>Durées de conservation</h2>',
    '<ul>',
    '<li><strong>Compte, notes, fichiers associés et données 2FA</strong> — jusqu’à la suppression du compte. Réactiver la 2FA remplace le secret et, après confirmation, les codes de secours.</li>',
    '<li><strong>Sessions</strong> — utilisables une heure au maximum. La déconnexion retire la session active, et la suppression du compte retire toutes ses sessions. Les sessions expirées sont nettoyées toutes les dix minutes.</li>',
    '<li><strong>Cookie anti-CSRF</strong> — cookie de session du navigateur. Les compteurs de connexion expirent après quinze minutes et sont purgés toutes les dix minutes.</li>',
    '<li><strong>Fichiers déposés sans compte</strong> — jusqu’au nettoyage du dossier temporaire ou au remplacement du conteneur applicatif.</li>',
    '<li><strong>Journaux techniques</strong> — durée déterminée par la configuration de rotation des journaux de l’instance.</li>',
    '</ul>',
    '<h2>Accès aux données</h2>',
    '<p>Les personnes chargées de l’exploitation locale peuvent accéder aux données nécessaires à leur mission. L’instance utilise l’application et sa base PostgreSQL locales.</p>',
    '<h2>Vos droits</h2>',
    '<p>Vous pouvez demander l’accès, la rectification, l’effacement, la limitation et, selon le traitement, la portabilité ou l’opposition. Vous pouvez aussi <a href="/account">supprimer votre compte</a> depuis Rempart ou <a href="https://www.cnil.fr/fr/plaintes">adresser une réclamation à la CNIL</a>.</p>',
    '<h2>Contact</h2>',
    '<p>Pour une question ou une demande concernant vos données, contactez l’équipe Rempart via ' + contact + '.</p>',
    '</main></body></html>',
  ].join('\n');
}

module.exports = privacyPage;
