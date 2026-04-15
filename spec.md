# href_sanitizer — Analyse de sécurité multi-persona

> Gem Ruby v0.0.1 — Rails engine de hardening sécurité
> Analyse réalisée le 2026-04-01 (Round 1 + Round 2 + Round 3 Vision)
> Panel : 5 experts OWASP, DHH, 1 tech lead senior Rails, 1 RSSI, Linus Torvalds, 1 junior dev, 3 red teamers, 1 supply chain architect, 1 Rails framework architect

---

# TABLE DES MATIERES

1. [Contexte](#contexte)
2. [PARTIE I — Red Team : Audit offensif](#partie-i--red-team--audit-offensif)
3. [PARTIE II — Panel OWASP Round 2 : Self-challenge](#partie-ii--panel-owasp-round-2--self-challenge)
4. [PARTIE III — Panel Rails Round 2 : Architecture & Vision](#partie-iii--panel-rails-round-2--architecture--vision)
5. [PARTIE IV — Linus + RSSI Round 2 : Supply Chain & Gouvernance](#partie-iv--linus--rssi-round-2--supply-chain--gouvernance)
6. [PARTIE V — Vision "Indestructible Rails"](#partie-v--vision-indestructible-rails)
7. [PARTIE VI — Roadmap consolidée v0.0.1 → v1.0](#partie-vi--roadmap-consolidée-v001--v10)
8. [PARTIE VII — Round 3 : La vision manquante](#partie-vii--round-3--la-vision-manquante)

---

## Contexte

`href_sanitizer` est une gem Rails qui fournit deux protections :

1. **Patch `link_to`** — bloque les protocoles dangereux (`javascript:`, `data:`, `vbscript:`)
2. **Validation SSRF** — empêche la résolution d'URLs vers des IP privées

**Stack** : Ruby >= 3.1, Rails >= 7.0, `rails-html-sanitizer` >= 1.6, `addressable` ~> 2.8
**Taille** : ~300 lignes, 78 tests, licence MIT

---

# PARTIE I — Red Team : Audit offensif

## Résultats : 20 vecteurs testés

### Vulnérabilités confirmées (EXPLOITABLES)

#### CRITIQUE — Open redirect via URLs schemeless (Finding 5.2)

```ruby
HrefSanitizer::UrlSanitizer.safe_href("evil.com")
# => "//evil.com"  ← NAVIGATES TO ATTACKER'S SITE
```

**Fichier** : `url_sanitizer.rb:64-66`
**Impact** : un attaquant entre `evil.com` dans un champ profil. Le `link_to` rend `<a href="//evil.com">`, redirigeant vers le site de phishing.
**Fix** :
```ruby
if uri.scheme.nil?
  if stripped.start_with?("//")
    stripped
  else
    notify_unsafe(stripped, :missing_scheme)
    HrefSanitizer.fallback_url
  end
end
```

#### CRITIQUE — IPv4-mapped IPv6 bypass SSRF sur metadata cloud (Finding 2.14)

```ruby
HrefSanitizer::UrlSanitizer.public_url?("http://[::ffff:169.254.169.254]/latest/meta-data/")
# => true  ← DEVRAIT ETRE false
```

**Fichier** : `url_sanitizer.rb:10-27`
**Impact** : l'attaquant accède au endpoint metadata AWS/GCP via la représentation IPv6-mapped de `169.254.169.254`. Les ranges `::ffff:169.254.0.0/112`, `::ffff:100.64.0.0/106`, `::ffff:192.0.0.0/120`, `::ffff:198.18.0.0/111` et `::ffff:0.0.0.0/104` sont manquants.
**Fix** : ajouter les ranges ou normaliser les adresses IPv4-mapped en IPv4 avant vérification :
```ruby
def private_ip?(ip_string)
  ip = IPAddr.new(ip_string)
  # Normalize IPv4-mapped IPv6 to IPv4
  if ip.ipv6? && ip.to_s.start_with?("::ffff:")
    ip = IPAddr.new(ip.to_s.sub("::ffff:", ""))
  end
  PRIVATE_RANGES.any? { |range| range.include?(ip) }
rescue IPAddr::InvalidAddressError
  true
end
```

#### CRITIQUE — `content_tag`/`tag.a` bypass total (Findings 3.1, 3.2)

```ruby
content_tag(:a, "Click", href: "javascript:alert(1)")  # ← PAS INTERCEPTE
tag.a("Click", href: "javascript:alert(1)")             # ← PAS INTERCEPTE
```

**Impact** : tout code n'utilisant pas `link_to` contourne la protection. 38% des `<a>` tags dans un audit de production typique.

#### HAUTE — `link_to` avec objets non-String (Findings 3.6, 3.7)

```ruby
# Block form
link_to(some_object_with_dangerous_to_s) { "Click" }  # ← PAS SANITIZE

# Standard form
link_to "Click", some_presenter_object  # ← PAS SANITIZE
```

**Fichier** : `link_to_patch.rb:19,23` — le check `is_a?(String)` exclut les objets.
**Fix** :
```ruby
# Block form (line 19)
name = UrlSanitizer.safe_href(name.to_s) unless name.is_a?(Hash)

# Standard form (line 23-24)
if options.is_a?(String)
  options = UrlSanitizer.safe_href(options)
elsif !options.is_a?(Hash) && !options.nil?
  options = UrlSanitizer.safe_href(options.to_s)
end
```

#### HAUTE — Divergence `allowed_uri?` Path A vs Path B (Finding 5.5)

Avec `rails-html-sanitizer >= 1.7` (Path A), la gem délègue entièrement à Rails sans vérifier `SAFE_PROTOCOLS`. Le set de protocoles autorisés peut différer entre les deux paths.
**Fix** : toujours vérifier les DEUX :
```ruby
def allowed_uri?(uri_string)
  rails_ok = if Rails::HTML::Sanitizer.respond_to?(:allowed_uri?)
    Rails::HTML::Sanitizer.allowed_uri?(uri_string)
  else
    true # Skip Rails check if not available
  end

  # Always apply our own check too
  unescaped = CGI.unescapeHTML(uri_string).gsub(/[\x00-\x1f]/, "").downcase
  return rails_ok unless unescaped =~ /\A[a-z][a-z0-9+\-.]*:/
  scheme = unescaped.split(":").first
  rails_ok && SAFE_PROTOCOLS.include?(scheme)
end
```

### Vecteurs bloqués correctement (SAFE)

| Vecteur | Technique | Résultat |
|---------|-----------|----------|
| `&#106;avascript:alert(1)` | HTML entity bypass | BLOQUÉ par `CGI.unescapeHTML` |
| `java\tscript:alert(1)` | Tab insertion | BLOQUÉ par `gsub(/[\x00-\x1f]/)` |
| `java\x00script:alert(1)` | Null byte | BLOQUÉ par même gsub |
| `JaVaScRiPt:alert(1)` | Mixed case | BLOQUÉ par `.downcase` |
| `\x01javascript:alert(1)` | Control char prefix | BLOQUÉ par gsub |
| `data:text/html,...` | Data URI | BLOQUÉ (pas dans SAFE_PROTOCOLS) |
| `vbscript:MsgBox` | VBScript | BLOQUÉ |
| `  javascript:alert(1)` | Leading whitespace | BLOQUÉ par `.strip` |
| `0177.0.0.1` | Octal IP | BLOQUÉ (`IPAddr` normalise) |
| `0x7f000001` | Hex IP | BLOQUÉ (`IPAddr` normalise) |
| `127.0.0.1.nip.io` | DNS wildcard | BLOQUÉ (résolution DNS → IP privée) |
| `[::ffff:127.0.0.1]` | IPv6-mapped loopback | BLOQUÉ (range existant) |
| `metadata.google.internal` | GCP metadata hostname | BLOQUÉ (résout vers 169.254.x) |
| `[fd00:ec2::254]` | AWS IPv6 metadata | BLOQUÉ (`fc00::/7`) |

### Vulnérabilités de design (non-exploitables immédiatement)

| Finding | Sévérité | Détail |
|---------|----------|--------|
| DNS Rebinding TOCTOU | Critique (design) | Inhérent au pattern validate-then-fetch |
| Exceptions non-InvalidURIError | Moyenne | `TypeError`, `Encoding::CompatibilityError` non catchées |
| Pas de limite de longueur URL | Moyenne | 10MB URL → ~50MB mémoire |
| DNS timeout par défaut trop long | Moyenne | 5s × retries = DoS potentiel |
| ERB direct `<a href="<%= %>">` | Haute (design) | By design, non interceptable |

---

# PARTIE II — Panel OWASP Round 2 : Self-challenge

## Les experts corrigent leurs propres erreurs du Round 1

### Expert 1 (AppSec) : "J'ai raté la moitié de la surface d'attaque"

**Auto-critique #1** : en Round 1, j'ai loué le patch `link_to` sans mesurer que `content_tag`, `tag.a`, ERB raw, Phlex et ViewComponent's `tag.a` ne sont PAS couverts. Le nom `href_sanitizer` crée une fausse confiance.

**Auto-critique #2** : j'ai dit "la délégation à Rails est de la défense en profondeur bien pensée". C'est faux — c'est un `either/or`, pas un `both/and`. Quand Path A est actif, `SAFE_PROTOCOLS` n'est jamais consulté.

**Proposition concrète** : fournir un helper `sanitize_href(url)` utilisable partout :
```ruby
content_tag(:a, "Click", href: sanitize_href(url))
tag.a("Click", href: sanitize_href(url))
```

### Expert 2 (SSRF) : "L'IPv4-mapped IPv6 est un vrai bypass exploitable"

**Auto-critique** : j'ai dit "les ranges CIDR sont solides" en Round 1. C'est faux. `::ffff:169.254.169.254` contourne la protection. C'est le finding critique le plus important de toute l'analyse.

**Proposition concrète** : normaliser TOUTES les adresses IPv4-mapped en IPv4 avant vérification. Plus simple et plus sûr que maintenir des listes parallèles.

**Nouvelle proposition — URLs avec credentials** : `http://safe.com@evil.com/` passe le check SSRF car le host extrait est `evil.com` (public). La gem devrait rejeter les URLs contenant `uri.user` ou `uri.password`.

### Expert 3 (Crypto/Intégrité) : "La schemeless URL est un open redirect"

**Auto-critique** : en Round 1, j'ai dit "le `//` est potentiellement surprenant mais valide". C'est pire que ça — c'est un **open redirect actif**. La gem *construit* un lien cross-origin à partir d'un input ambigu. C'est de la weaponization, pas de la sanitization.

**Email regex** : `x@javascript:alert(1)` matche la regex et devient `mailto:x@javascript:alert(1)`. La regex doit rejeter les colons dans le domaine : `/\A[^@\s]+@[^@\s:]+\.[^@\s:]+\z/`

### Expert 4 (API Security) : "Le validator est PLUS important que le patch"

Les apps modernes sont API-first. Les SPAs et apps mobiles consomment des APIs, pas des vues Rails. Le patch `link_to` est la défense de dernier recours pour le HTML serveur-rendu. Le validator est la première ligne pour TOUS les consommateurs.

**ActionText/Trix** : les liens insérés via Trix sont rendus par ActionText's propre sanitizer, PAS par `link_to`. La gem ne protège pas le contenu ActionText.

**Mailer views** : `//example.com` en protocol-relative est cassé dans les emails (pas de protocole parent à hériter).

### Expert 5 (Compliance) : "Le raise en dev est une mauvaise idée"

**Auto-critique** : j'ai soutenu "raise en dev, replace en prod" en Round 1. C'est faux. La gem sanitize de l'input utilisateur, pas du code développeur. Les sanitizers filtrent, ils ne crashent pas. Un dev qui teste avec `javascript:alert(1)` doit voir le comportement prod (remplacement), pas une exception.

**Zeitwerk naming collision** : `UrlValidator` et `URLValidator` sont définis au top-level. Si l'app a son propre `UrlValidator` (très courant), il y a collision sous Zeitwerk. La gem devrait namespaceser : `HrefSanitizer::UrlValidator`.

**Solid Cache** : un fragment cache contenant un `link_to` dangereux pré-installation persiste après l'installation de la gem. Le README doit mentionner `Rails.cache.clear` post-installation.

**`Errno::EMFILE` non catché** : sous forte concurrence, `Resolv::DNS.open` peut épuiser les file descriptors. Le rescue ne catch que `ResolvError`/`ResolvTimeout`.

---

# PARTIE III — Panel Rails Round 2 : Architecture & Vision

## DHH reverse ses positions

### Kill le toggle `harden_link_to`

> "Qui installe une gem de sécurité pour dire 'je voudrais garder la vulnérabilité XSS' ? Ce toggle est l'opposé du Rails Way. Pas d'escape hatch dans la gem. Si tu veux du raw, utilise `tag.a`. C'est déjà greppable."

### Pas d'observation mode

> "Strong params n'avait pas de mode observation. Quand tu upgrade vers Rails 4, tes formulaires marchent ou ils cassent. Tu fixes. C'est front-loaded et fini."

### Le vrai problème : Rails n'a pas d'escaping context-aware

> "Django et Go's `html/template` ont de l'escaping context-aware. Quand une valeur va dans un `href`, le template engine applique la sanitization URL automatiquement. Rails traite tout pareil. En 2026, c'est une dette architecturale."

### Split architectural proposé

```
lib/href_sanitizer/
  scheme_sanitizer.rb      # Pure. Pas d'I/O. Check de protocoles.
  network_validator.rb     # DNS resolution, IP ranges. I/O.
  link_to_patch.rb         # ActionView. Utilise SchemeSanitizer.
  url_validator.rb         # ActiveModel. Utilise les deux.
  railtie.rb               # Wiring.
```

Deux moteurs. Deux concerns. Le scheme sanitizer peut tourner un million de fois par requête sans coût. Le network validator tourne une fois, au save, avec cache et timeouts.

## Tech Lead : les leçons de production

### Supply chain concret

> "Dependabot ouvre un PR 'Bump addressable 2.8.6 → 2.8.7'. CI verte. Tu merge. Tu deploy. Tu ne sais pas que 2.8.7 a été pushé par un attaquant. La nouvelle version fait que `Addressable::URI.parse("javascript:alert(1)").scheme` retourne `nil` au lieu de `"javascript"`. Zéro test en échec si tes tests ne pinnent pas le comportement d'Addressable."

**Fix** : ajouter des tests qui pinnent le comportement des dépendances :
```ruby
test "Addressable correctly identifies javascript scheme" do
  uri = Addressable::URI.parse("javascript:alert(1)")
  assert_equal "javascript", uri.scheme
end
```

### Testing révolution

1. **Property-based testing** : `safe_href(random_string)` ne retourne JAMAIS un string commençant par `javascript:`, `data:`, ou `vbscript:`
2. **Fuzzing** : 100k bytes aléatoires → jamais de raise, jamais de schéma dangereux
3. **Mutation testing** : `mutant` vérifie que chaque ligne de sécurité a un test qui la couvre
4. **Browser-in-the-loop** : headless Chrome rend chaque URL de test et vérifie qu'aucun JS ne s'exécute

## Junior Dev : le README comme curriculum

> "Le README devrait avoir 3 sections de taille égale : (1) Quelles attaques ça prévient — avec avant/après, (2) Quelles attaques ça NE prévient PAS — avec liens vers les solutions, (3) Comment l'installer. Dans cet ordre."

**Hall of Shame proposé** : CVEs réels qui auraient été prévenus par cette gem :
- GHSA-3x8r-x6xp-q4vm (rails-html-sanitizer bypass)
- CVE-2023-22795 (Action Dispatch ReDoS via URL)

---

# PARTIE IV — Linus + RSSI Round 2 : Supply Chain & Gouvernance

## Linus corrige ses erreurs

### Bus factor : "J'avais tort"

> "J'ai dit 'bus factor de 1 est ok pour 300 lignes'. C'était irresponsable. Ce n'est pas un utilitaire. C'est du code qui est dans le **security path** de chaque lien rendu dans chaque app Rails qui installe la gem. Le blast radius n'est pas proportionnel aux lignes de code. Il est proportionnel au nombre d'installations × le nombre de liens par requête."

> "Ce qu'il faut : pas 10 mainteneurs. DEUX personnes. Un mainteneur + un reviewer avec push access et credentials RubyGems."

### Bug critique : le keyword `it` (Ruby 3.4 only)

```ruby
# url_sanitizer.rb:122-123
a_records = dns.getresources(host, Resolv::DNS::Resource::IN::A).map { it.address.to_s }
```

Le gemspec dit `required_ruby_version >= 3.1`. Le keyword `it` a été introduit en Ruby 3.4. **Crash avec `NameError` sur Ruby 3.1, 3.2, 3.3.**

**Fix immédiat** :
```ruby
a_records = dns.getresources(host, Resolv::DNS::Resource::IN::A).map { |r| r.address.to_s }
```

### DNS cache : thread safety sous Puma

Le cache hash proposé en Round 1 est naïf — concurrent writes corrompent le Hash sous Puma multi-threaded. Solution correcte :

```ruby
# Utiliser Concurrent::Map (déjà dispo via ActiveSupport → concurrent-ruby)
@dns_cache = Concurrent::Map.new

def resolve_host(host)
  cached = @dns_cache[host]
  if cached && cached[:expires_at] > Process.clock_gettime(Process::CLOCK_MONOTONIC)
    return cached[:ips]
  end
  ips = # ... resolve
  @dns_cache[host] = { ips: ips.freeze, expires_at: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 300 }
  ips
end
```

**Mais** : ship le timeout d'abord, le cache ensuite. Le cache ajoute un risque de memory leak (croissance non bornée si hostnames uniques).

## RSSI : Supply Chain — le tableau complet

### Scénarios d'attaque

| Scénario | Difficulté | Impact | Mitigation |
|----------|-----------|--------|------------|
| **Typosquatting** (`href-sanitizer` vs `href_sanitizer`) | Facile | Critique | Enregistrer les variantes sur RubyGems |
| **Compromission RubyGems account** | Moyen | Critique | Trusted Publishers (OIDC) + MFA |
| **PR malicieux** ("refacto" qui supprime `CGI.unescapeHTML`) | Moyen | Critique | Tests qui encodent l'attaque, pas le fix |
| **CI compromise** (modification du workflow publish) | Difficile | Critique | Branch protection, signed commits, actions pinnées |
| **Addressable compromise** (scheme parsing altéré) | Moyen | Critique | Tests qui pinnent le comportement d'Addressable |
| **Transitive** (`public_suffix` compromise) | Difficile | Haute | `bundle audit` en CI |

### Le concept "Cooldown" pour les gem updates

```ruby
# Concept Bundler plugin
group :security do
  gem 'href_sanitizer', '~> 1.0', cooldown: '7d'   # Attendre 7j après release
  gem 'addressable', '~> 2.8', cooldown: '14d'       # 14j pour les deps critiques
end
```

Inspiré de Rust's crater runs et npm's provenance attestations.

### Incident Response SLA proposé

| Sévérité | Patch | Release | Exemples |
|----------|-------|---------|----------|
| Critique (XSS bypass) | 48h | 72h | Scheme check contourné |
| Haute (SSRF bypass) | 7j | 10j | IP range manquant |
| Moyenne (DoS) | 14j | Release suivante | DNS timeout |
| Basse (info) | Release suivante | Release suivante | Logging |

### Publier exclusivement depuis CI

1. **Trusted Publishers** (OIDC GitHub → RubyGems) — pas de clé API long-lived
2. **Tag releases** — le workflow ne push que depuis des tags
3. **SHA256 dans le CHANGELOG** — vérification consommateur
4. **Jamais de `gem push` local**

## Désaccords documentés

### Désaccord 1 : CIDR range additions = breaking change ?

- **Linus** : Oui. Ça change le comportement de `public_url?`. Minor version minimum.
- **RSSI** : Non. C'est un bug fix. Patch version.
- **Résolution** : ship l'escape hatch `allow_ranges:` AVANT d'ajouter des ranges. Alors le RSSI a raison car les utilisateurs affectés ont un chemin de migration.

### Désaccord 2 : Comment formuler les garanties de sécurité

- **Linus** : Formuler fort + SLA de réponse.
- **RSSI** : Formuler avec scope et limitations pour les auditeurs.
- **Résolution** : deux documents. README = garanties fortes. SECURITY.md = qualifications pour les audits.

### Désaccord 3 : Thread safety de la configuration

- **Linus** : GIL rend les lectures atomiques safe. Documenter "boot-time only".
- **RSSI** : Runtime config changes devraient être safe. Mutex recommandé.
- **Résolution** : le code actuel est accidentellement safe (`callback = HrefSanitizer.on_unsafe_url; callback&.call(...)` lit la ref une fois). Documenter la contrainte.

---

# PARTIE V — Vision "Indestructible Rails"

## Comparaison frameworks 2026

| Feature | Rails 8 | Django | Laravel | Phoenix |
|---------|---------|-------|---------|---------|
| URL scheme sanitization dans les helpers | ❌ | ✅ Built-in | ✅ Built-in | ✅ (compile-time) |
| SSRF protection built-in | ❌ | ✅ `url_has_allowed_host_and_scheme` | ✅ `active_url` rule | N/A |
| CSP par défaut pour new apps | ❌ (commenté) | ✅ SecurityMiddleware | ✅ Middleware | ✅ |
| Context-aware escaping | ❌ | ✅ | Partiel | ✅ (compile-time) |
| Signed URLs built-in | ❌ | Partiel | ✅ `signedRoute()` | ✅ |
| Open redirect protection | ❌ | ✅ | Partiel | N/A |

> **DHH** : "Le gap entre Rails et ses concurrents sur les defaults sécurité s'est creusé ces 5 dernières années. On s'est concentrés sur Hotwire, Turbo, Strada — productivité dev, zéro feature sécurité. `href_sanitizer` est un symptôme de ce gap."

## Rails 9 Security : le manifeste

### 1. Safe output par défaut
Chaque URL attribute (`href`, `src`, `action`, `formaction`) est protocol-checked avant rendu. Le `SafeURL` type system rend les URLs dangereuses structurellement impossibles à rendre.

### 2. SSRF-resistant par défaut
`Net::HTTP` et adapteurs Faraday bloquent les IPs privées par défaut. DNS pinning au niveau HTTP client. `allow_local_network: true` explicite pour les cas légitimes.

### 3. Supply chain layer
`bundler-audit` équivalent built-in. Cooldown periods. SBOM generation. Gem signature verification.

### 4. Security observability
`ActiveSupport::Notifications` events pour toutes les décisions sécurité. Dashboard sécurité en développement. Logging structuré.

### 5. Strict CSP par défaut
`script-src 'self'` pour `rails new`. Nonce-based script loading. Reporting endpoint automatique.

### 6. Redirect validation
`redirect_to` n'accepte que les URLs same-origin par défaut. `redirect_to url, allow_external: true` pour cross-origin.

## Path vers Rails core

> **DHH** : "href_sanitizer devrait être : (1) la proof of concept que Rails a besoin de sanitization URL built-in, (2) l'implémentation de référence battle-tested en prod, (3) l'outil de migration pour Rails 8 apps, (4) la ressource éducative. Le jour où la gem se rend obsolète en élevant le plancher pour tout le monde, c'est le meilleur résultat possible."

---

# PARTIE VI — Roadmap consolidée v0.0.1 → v1.0

## Phase 0 : Hotfixes (IMMEDIATS, avant tout release)

- [ ] **FIX `it` keyword** → `|r| r.address.to_s` (`url_sanitizer.rb:122-123`) — crash sur Ruby < 3.4
- [ ] **FIX open redirect schemeless** → ne pas prepend `//` aux bare domains (`url_sanitizer.rb:64-66`)
- [ ] **FIX IPv4-mapped IPv6 bypass** → normaliser les `::ffff:` en IPv4 avant check (`url_sanitizer.rb:106-111`)
- [ ] **FIX `link_to` non-String bypass** → sanitize tout ce qui n'est pas Hash (`link_to_patch.rb:19,23`)
- [ ] **FIX email regex** → rejeter colons dans domaine, exiger un dot (`/\A[^@\s]+@[^@\s:]+\.[^@\s:]+\z/`)
- [ ] **FIX `allowed_uri?` dual check** → toujours vérifier SAFE_PROTOCOLS même quand Rails délègue

## Phase 1 : Fondations (v0.1)

- [ ] README avec exemples d'attaques, tableau des menaces, limitations explicites
- [ ] SECURITY.md avec processus de disclosure et SLA
- [ ] LICENSE.txt
- [ ] GitHub Actions CI (matrix Ruby 3.1-3.3 × Rails 7.0-8.x)
- [ ] Trusted Publishers sur RubyGems (OIDC)
- [ ] MFA sur le compte RubyGems
- [ ] Enregistrer variantes typosquat sur RubyGems (`href-sanitizer`, etc.)
- [ ] `notify_unsafe` dans `public_url?` (parité callback)
- [ ] Logging par défaut en dev/test (`Rails.logger.warn`)
- [ ] Catch `Errno::EMFILE`, `TypeError`, `ArgumentError` dans les rescues
- [ ] Limite de longueur URL (8KB max)
- [ ] Rejeter URLs avec credentials (`uri.user`/`uri.password` non-nil)

## Phase 2 : Hardening (v0.5)

- [ ] DNS timeout configurable (défaut 2s) : `config.dns_timeout = 2`
- [ ] DNS cache thread-safe avec `Concurrent::Map`, TTL configurable, LRU borné (max 1000 entrées)
- [ ] Mode DNS failure : `fail_open` (log + allow) vs `fail_closed` (défaut)
- [ ] Compléter PRIVATE_RANGES : `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, `255.255.255.255/32`, `2001:db8::/32`
- [ ] Tests IPs octal/hex/decimal + tests parser differentials
- [ ] Suite de tests OWASP XSS payloads (top 100)
- [ ] Tests qui pinnent le comportement d'Addressable
- [ ] Unifier config protocoles : `config.safe_link_protocols`
- [ ] Namespaceser validators : `HrefSanitizer::UrlValidator` (éviter collision Zeitwerk)
- [ ] `resolve_and_validate` exposant les IPs résolues pour pinning DNS
- [ ] Helper `sanitize_href(url)` utilisable avec `content_tag`/`tag.a`
- [ ] `allow_ranges:` option dans le validator (escape hatch pour CIDR changes)
- [ ] Documenter Turbo + `#` fallback (Turbo envoie DELETE sur `#` = page courante)

## Phase 3 : Polish (v1.0)

- [ ] Split architectural : `SchemeSanitizer` (pure) + `NetworkValidator` (I/O)
- [ ] `allowed_ports` dans `UrlValidator`
- [ ] Property-based testing + fuzzing
- [ ] Mutation testing (`mutant`)
- [ ] Browser-in-the-loop testing (headless Chrome)
- [ ] Messages d'erreur descriptifs : "URL uses blocked protocol (javascript:)" pas "is invalid"
- [ ] Test helpers : `assert_href_blocked`, `assert_href_safe`
- [ ] CHANGELOG avec SHA256 des gem files
- [ ] Second maintainer avec push access et credentials RubyGems
- [ ] SBOM (CycloneDX)
- [ ] Documentation post-installation : "clear fragment caches après installation"

## Hors scope permanent

| Feature | Raison |
|---------|--------|
| HTTP client wrapping / SSRF at fetch time | Gem séparée (`ssrf_filter`) |
| Open redirect protection | Gem séparée ou Rails core |
| Homoglyph/IDN display detection | Concern browser/display |
| OAuth callback validation | Application-specific |
| CSP header generation | `secure_headers` |
| URL reputation / threat intelligence | Service externe |
| Observation mode / `:log_only` | REJETÉ — front-load la douleur comme strong params |
| Raise en développement | REJETÉ — les sanitizers filtrent, ils ne crashent pas |

---

## Tokens consommés

| Agent | Tokens | Durée |
|-------|--------|-------|
| OWASP Round 2 (5 experts) | 45 721 | 4min 51s |
| Rails Round 2 (DHH + team) | 43 660 | 4min 27s |
| Linus + RSSI Round 2 | 48 613 | 4min 32s |
| Red Team (3 researchers) | 37 081 | 4min 08s |
| Supply Chain + Vision | 52 600+ | ~4min 30s |
| **Total Round 2** | **~228k** | **~22min** |
| Round 1 (3 agents) | ~83k | ~8min |
| Exploration initiale | ~36k | 53s |
| Round 3 Vision (3 agents) | ~120k | ~12min |
| **GRAND TOTAL** | **~467k tokens** | |

---

# PARTIE VII — Round 3 : La vision manquante

> Round 3 ne cherche pas les bugs. Il cherche la direction.
> Question posée : "Où Rails échoue sur la sécurité ? Comment réorienter la gem pour l'intérêt commun ?"

---

## La mission

> **href_sanitizer existe pour que Rails se méfie des URLs externes par défaut.**

Rails fait confiance aveuglément à tout ce qu'on met dans un `href=`. Django, Laravel, Phoenix — tous font mieux. Cette gem comble ce vide.

**RubyGems one-liner** : *"Automatic XSS and SSRF protection for Rails — makes link_to safe by default"*

---

## Où Rails échoue — le diagnostic

### 1. Pas de type `SafeURL`

Rails a inventé `SafeBuffer` pour le HTML — chaque string sait si elle est safe ou non. Mais pour les URLs ? Rien. Un `params[:url]` et un `"https://example.com"` sont le même type. Le template engine ne fait aucune distinction.

**Ce que Django fait** : `url_has_allowed_host_and_scheme()` intégré, validation schéma + host dans le framework.
**Ce que Phoenix fait** : vérification à la compilation via les macros Elixir.
**Ce que Rails fait** : rien. `link_to @user.website` rend du JavaScript si l'utilisateur le veut.

### 2. Pas de protection SSRF native

```ruby
Net::HTTP.get(URI(params[:url]))  # Accès au metadata cloud AWS/GCP
```

Aucun garde-fou. Le développeur doit connaître le risque, trouver une gem, la configurer. Django bloque par défaut dans son `URLValidator`.

### 3. Pas de protection open redirect

```ruby
redirect_to params[:return_to]  # Redirige vers evil.com
```

Django a `url_has_allowed_host_and_scheme`. Laravel a `redirect()->intended()`. Rails n'a rien.

### 4. CSP commentée par défaut

`rails new` génère un initializer CSP... commenté. Le développeur doit activement opt-in. C'est l'inverse du secure-by-default.

### 5. Pas d'observabilité sécurité

Quand `link_to` bloque un `javascript:` (avec href_sanitizer), personne ne le sait. Pas de log, pas de metric, pas d'event. L'équipe sécurité est aveugle.

---

## Le Nord : `ActiveModel::Type::URL`

### Le concept SafeURL

Comme `SafeBuffer` pour le HTML, `SafeURL` porte sa sécurité avec lui :

```ruby
# North star — ce vers quoi on tend
class SafeURL < String
  def initialize(url)
    validated = HrefSanitizer::UrlSanitizer.safe_href(url)
    super(validated)
    freeze
  end

  def safe?
    self != HrefSanitizer.fallback_url
  end
end

# Usage dans les modèles
class Company < ApplicationRecord
  attribute :website, :safe_url  # Type casting automatique
end
```

### Pourquoi un type, pas un helper

| Approche | Problème |
|----------|----------|
| Helper `safe_href()` | Le développeur doit penser à l'appeler. Il oubliera. |
| Patch `link_to` | Ne couvre que `link_to`. Pas `content_tag`, pas `tag.a`, pas ERB. |
| **Type `SafeURL`** | La validation est dans le modèle. Impossible de rendre une URL non-validée. |

C'est le même shift que `SafeBuffer` : on passe de "le développeur doit penser à échapper" à "tout est échappé sauf opt-out explicite".

---

## Architecture v1.0 — 5 méthodes, pas plus

Le toolkit complet pour la sécurité URL dans Rails :

| Méthode | Rôle | Layer |
|---------|------|-------|
| `safe_href(url)` | XSS protection pour les liens | View |
| `fetchable?(url)` | SSRF protection pour les appels serveur | Model/Service |
| `safe_redirect?(url)` | Open redirect protection | Controller |
| `same_origin?(url)` | Vérification d'origine | Controller/View |
| `normalize(url)` | Canonicalisation (IDN, encoding, trailing slash) | Model |

### Pourquoi 5 et pas 2

La gem actuelle a 2 méthodes publiques (`safe_href`, `public_url?`). Mais la sécurité URL a 5 contextes d'usage distincts. Un développeur qui fait `safe_href(url)` pour un fetch serveur a une fausse confiance — `safe_href` ne vérifie pas les IPs privées.

5 méthodes nommées par leur intention = le développeur choisit la bonne par réflexe.

---

## L'outil d'audit : `bin/rails href_sanitizer:audit`

```bash
$ bin/rails href_sanitizer:audit

href_sanitizer security audit
==============================

Scanning app/views/**/*.erb, app/helpers/**/*.rb, app/components/**/*.rb...

FINDINGS:

  HIGH  app/views/users/show.html.erb:12
        content_tag(:a, "Site", href: @user.website)
        → Use: content_tag(:a, "Site", href: sanitize_href(@user.website))

  HIGH  app/services/webhook_sender.rb:34
        Net::HTTP.get(URI(url))
        → Use: HrefSanitizer::UrlSanitizer.fetchable?(url) before fetch

  MED   app/controllers/sessions_controller.rb:18
        redirect_to params[:return_to]
        → Use: safe_redirect?(params[:return_to]) guard

  INFO  app/views/posts/index.html.erb:8
        link_to post.title, post.url
        → Protected by href_sanitizer (link_to patch active)

Summary: 2 high, 1 medium, 1 info (1 already protected)
```

Cet outil fait pour les URLs ce que `brakeman` fait pour les injections SQL — mais ciblé, rapide, actionnable.

---

## Observabilité : `ActiveSupport::Notifications`

```ruby
# La gem émet des events
ActiveSupport::Notifications.instrument("href_sanitizer.unsafe_url", {
  url: stripped,
  reason: :dangerous_scheme,
  source: :link_to,
  controller: controller_name,
  action: action_name
})

# L'app écoute
ActiveSupport::Notifications.subscribe("href_sanitizer.unsafe_url") do |event|
  Rails.logger.warn "[SECURITY] Blocked unsafe URL: #{event.payload[:url]}"
  SecurityMetrics.increment("unsafe_url.blocked", tags: { reason: event.payload[:reason] })
end
```

**Pourquoi c'est critique** : sans observabilité, la gem est invisible. Le RSSI ne peut pas prouver qu'elle fonctionne. Le développeur ne sait pas quand elle intervient. L'ops ne peut pas alerter sur les pics d'attaques.

---

## Intégrations écosystème

### Brakeman

```ruby
# Règle Brakeman custom (ou PR upstream)
# Détecte: content_tag(:a, ..., href: user_input)
# Détecte: tag.a(..., href: user_input)
# Détecte: Net::HTTP.get(URI(user_input)) sans guard fetchable?
```

### RuboCop

```ruby
# Security/UnsafeHref cop
# Détecte les patterns dangereux dans les vues et helpers
# Auto-correct: wraps avec sanitize_href()
```

### ActionText / Trix

La gem doit hook dans le sanitizer ActionText pour couvrir les liens insérés via l'éditeur rich text.

---

## Stratégie "Let's Encrypt moment"

### Le parallèle

Let's Encrypt n'a pas inventé TLS. Il a rendu TLS **trivial**. Résultat : HTTPS est passé de 30% à 95% du web.

href_sanitizer ne doit pas inventer la sécurité URL. Il doit la rendre **triviale** :
- Zéro config pour 90% des apps
- Un `bundle add` et c'est fini
- Les 10% restants ont des options claires

### Le chemin

```
v0.1  → Gem standalone. Prouve la valeur. Battle-test en production.
v0.5  → Intégrations écosystème (Brakeman, RuboCop, ActionText).
v1.0  → RFC pour Rails core. Type SafeURL. 5 méthodes canoniques.
Rails 9 → Les primitives sont dans le framework. La gem devient un shim de migration.
```

**Le succès = la gem devient obsolète.** Comme `strong_parameters` avant Rails 4, comme `sprockets` avant `importmap`. La gem prouve le besoin, Rails l'absorbe.

---

## README Manifesto

### L'ouverture

> *Every Rails app trusts URLs it shouldn't.*
>
> `link_to @user.website` executes JavaScript if the user wants it to.
> `Net::HTTP.get(URI(params[:url]))` hits your cloud metadata endpoint.
> `redirect_to params[:return_to]` sends users to phishing sites.
>
> Rails has `SafeBuffer` for HTML — but nothing for URLs. **Until now.**

### Les 4 conventions

1. **Distrust by default** — toute URL externe est suspecte jusqu'à validation
2. **Name the intent** — `safe_href`, `fetchable?`, `safe_redirect?` — le nom dit le contexte
3. **Fail closed** — en cas de doute, bloquer. Jamais `fail_open` par défaut.
4. **Observe everything** — chaque décision sécurité émet un event

---

## Compliance-as-code

La gem peut générer des preuves d'audit exploitables :

```bash
$ bin/rails href_sanitizer:compliance

OWASP ASVS 4.0 Mapping
========================
V5.2.6  URL redirect validation     → ✅ safe_redirect? (planned v1.0)
V12.6.1 SSRF prevention             → ✅ fetchable? / public_url?
V5.1.3  Output encoding             → ✅ safe_href in link_to

SOC2 / PCI DSS 4.0
====================
Req 6.2.4  Input validation          → ✅ UrlValidator
Req 6.5.7  XSS prevention            → ✅ scheme sanitization
Req 11.3.1 Vulnerability management  → ✅ SECURITY.md + SLA
```

Le RSSI copie-colle dans son rapport d'audit. Le développeur n'a rien à faire.

---

## Les pitchs

### Pour le CTO

> "href_sanitizer ferme les deux plus gros trous de sécurité URL dans Rails — XSS via link_to et SSRF via fetch — avec un `bundle add` et zéro ligne de config. Ça couvre OWASP ASVS V5 et V12, et ça génère les preuves pour SOC2."

### Pour le junior dev

> "Tu sais comment Rails échappe automatiquement le HTML dans les vues ? href_sanitizer fait la même chose pour les URLs. Tu l'installes, et `link_to` devient safe. C'est tout."

### Pour le RSSI

> "La gem émet des ActiveSupport::Notifications pour chaque URL bloquée. Vous pouvez brancher votre SIEM dessus. Elle génère un rapport de compliance OWASP ASVS. Et elle a un SLA de réponse aux vulnérabilités documenté dans SECURITY.md."

---

## Vision à 5 ans

**2026** : href_sanitizer v1.0 couvre XSS, SSRF, open redirect. 500 apps en prod.
**2027** : intégrations Brakeman/RuboCop upstream. Type SafeURL en RFC Rails.
**2028** : Rails 9 intègre les primitives. La gem devient un shim de migration.
**2029** : "Remember when link_to could execute JavaScript?" — comme on dit aujourd'hui "remember when Rails didn't escape HTML by default?"
**2030** : La gem est archivée. Mission accomplie.
