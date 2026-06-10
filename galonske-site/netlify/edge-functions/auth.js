// ════════════════════════════════════════════════════════════════
//  auth.js — Authentification HTTP Basic, gérée CÔTÉ SERVEUR (edge)
//
//  Pourquoi c'est une VRAIE protection (contrairement à l'ancienne) :
//   · Le mot de passe vit dans une variable d'environnement Netlify
//     (SITE_PASSWORD). Il n'est JAMAIS envoyé au navigateur.
//   · Tant que l'authentification échoue, AUCUN contenu du site
//     n'est servi : le visiteur ne reçoit qu'une réponse « 401 ».
//   · Impossible de lire le code source pour contourner : il n'y a
//     rien à lire tant qu'on n'est pas authentifié.
//
//  Cette fonction s'exécute AVANT que la moindre page ne soit livrée.
// ════════════════════════════════════════════════════════════════

export default async (request, context) => {
  const expectedUser = Deno.env.get("SITE_USER") || "client";
  const expectedPass = Deno.env.get("SITE_PASSWORD");

  // Garde-fou : si aucun mot de passe n'est configuré, on bloque tout
  // plutôt que de risquer d'ouvrir le site par erreur.
  if (!expectedPass) {
    return new Response(
      "Site non configuré : la variable SITE_PASSWORD est manquante.",
      { status: 503 }
    );
  }

  const header = request.headers.get("authorization") || "";
  const [scheme, encoded] = header.split(" ");

  if (scheme === "Basic" && encoded) {
    let decoded = "";
    try {
      decoded = atob(encoded);
    } catch (_e) {
      decoded = "";
    }
    const sep = decoded.indexOf(":");
    const user = decoded.slice(0, sep);
    const pass = decoded.slice(sep + 1);

    if (user === expectedUser && pass === expectedPass) {
      // ✅ Authentifié → on laisse la requête continuer vers le site.
      return context.next();
    }
  }

  // ❌ Non authentifié → on réclame les identifiants.
  // Le navigateur affiche alors sa fenêtre de connexion native.
  return new Response("Authentification requise.", {
    status: 401,
    headers: {
      "WWW-Authenticate":
        'Basic realm="Site prive - Cedric Galonske", charset="UTF-8"',
    },
  });
};
