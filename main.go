// mdns-aaaa-responder : repond a la place de Windows aux
// questions mDNS AAAA qui visent ce PC, mais SEULEMENT aux appareils qui les
// posent en boucle (et aux produits Amazon).
//
// Pourquoi (mesure du 2026-10-26) : un Echo Show et un autre appareil Amazon
// redemandaient sans fin l'AAAA du nom .local d'un PC Windows. Le PC n'a pas
// d'IPv6 (le client NordVPN, composant Ipv6LeakBlocker, le coupe sur toutes les
// cartes et le recoupe en quelques secondes si on le reactive), Windows repond
// donc par un NSEC « pas d'AAAA », que les appareils Amazon ignorent : jusqu'a
// 3 400 paquets mDNS/s, Wi-Fi du reseau local inutilisable. Bug Fire OS connu,
// sans correctif (community.amazondeveloper.com, fil 28820). Le seul remede
// rapporte : leur donner une vraie reponse AAAA, qu'ils gardent en cache.
//
// L'adresse annoncee est une adresse lien-local qui n'existe sur aucune carte.
// Un client qui la retiendrait pourrait perdre du temps a l'essayer avant
// l'IPv4 : rien ne garantit le repli. D'ou les precautions :
//   - on ne repond qu'aux demandeurs qui bouclent (seuil par source) ou listes ;
//   - question QU : reponse unicast, comme demande. Question QM : reponse
//     UNICAST d'abord, ce qui est un ECART VOLONTAIRE a la RFC 6762 §6 (elle
//     veut du multicast) pour que le reste du reseau ne voie pas l'adresse ;
//     un client conforme peut l'ignorer, d'ou le repli suivant ;
//   - repli : si la source boucle encore apres repliApres reponses unicast, on
//     lui repond en MULTICAST, que tout le reseau recoit et peut mettre en
//     cache. Ces reponses portent un TTL court (-ttl-repli, 120 s) ; chaque
//     nouvelle reponse le renouvelle, donc les autres appareils peuvent garder
//     l'adresse tant que le repli dure : le TTL court ne sert qu'a l'oublier vite
//     APRES la derniere annonce (et l'avis de retrait au demarrage l'efface) ;
//   - un produit Amazon (prefixe MAC de la table ARP, oui_amazon.go) passe en
//     multicast des sa premiere question, sans essai unicast ;
//   - une source deja reconnue est servie des sa premiere question ;
//   - au demarrage, et avec -retrait, un avis de retrait (TTL 0) efface
//     l'adresse des caches (la premiere version la diffusait a tout le reseau) ;
//   - une vraie AAAA publiee pour ce nom nous fait taire tant qu'au moins une
//     est valide (TTL ou avis de retrait, chacune suivie a part) : NordVPN
//     recoupe l'IPv6 en quelques secondes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var groupeMDNS = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

type config struct {
	nom      string
	ipv6     net.IP
	ipv4     net.IP // nil = pas d'enregistrement A additionnel
	ttl      uint32
	ttlRepli uint32          // TTL des reponses multicast de repli, vues par tout le reseau
	seuil    int             // questions d'une meme source dans la fenetre pour la juger « en boucle »
	fenetre  time.Duration   //
	toujours map[string]bool // sources servies d'office (IPv4 en texte)
	etat     string          // fichier d'etat pour heal-stack (vide = aucun)
	carte    *net.Interface
}

type stats struct {
	vues, servies, retenues, ignorees int
}

func main() {
	nomDefaut := ""
	if h, err := os.Hostname(); err == nil {
		nomDefaut = h + ".local"
	}
	nom := flag.String("nom", nomDefaut, "nom mDNS a defendre")
	ip4 := flag.String("ip", "", "adresse IPv4 de ce PC sur le reseau local (OBLIGATOIRE : choisit la carte d'ecoute)")
	ip6 := flag.String("ipv6", "fe80::aaaa", "adresse IPv6 annoncee (lien-local, ne doit exister sur aucune carte)")
	ttl := flag.Uint("ttl", 3600, "duree de validite annoncee en unicast, en secondes")
	ttlRepli := flag.Uint("ttl-repli", 120, "duree de validite des reponses multicast de repli, en secondes")
	seuil := flag.Int("seuil", 5, "questions AAAA d'une meme source dans la fenetre pour lui repondre")
	fenetre := flag.Duration("fenetre", 10*time.Second, "fenetre de comptage du seuil")
	toujours := flag.String("toujours", "", "IPv4 servies d'office, separees par des virgules")
	avecA := flag.Bool("avec-a", false, "joindre aussi l'enregistrement A (meme valeur que Windows)")
	retrait := flag.Bool("retrait", false, "envoyer seulement l'avis de retrait (TTL 0) puis quitter")
	journal := flag.String("journal", "", "fichier journal (vide = sortie standard)")
	etat := flag.String("etat", "", "fichier d'etat JSON reecrit toutes les 30 s au plus (sonde heal-stack)")
	macTest := flag.String("mac-de", "", "diagnostic : afficher la MAC (table ARP) de ces IPv4, separees par des virgules, puis quitter")
	flag.Parse()

	if *macTest != "" {
		for _, s := range strings.Split(*macTest, ",") {
			ip := net.ParseIP(strings.TrimSpace(s))
			cfg, err := preparer("x.local", *ip4, "fe80::1", 1, false)
			if err != nil {
				log.Fatal(err)
			}
			mac := macDe(ip, cfg.carte.Index)
			fmt.Printf("%s MAC=%s amazon=%v (carte %s, index %d)\n", s, mac, estMacAmazon(mac), cfg.carte.Name, cfg.carte.Index)
		}
		return
	}

	if *journal != "" {
		if st, err := os.Stat(*journal); err == nil && st.Size() > 5<<20 {
			os.Rename(*journal, *journal+".1")
		}
		f, err := os.OpenFile(*journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(f)
	}

	if *ip4 == "" {
		log.Fatal("l'option -ip est obligatoire : adresse IPv4 de ce PC sur le reseau local (ex. -ip 192.168.1.10)")
	}
	cfg, err := preparer(*nom, *ip4, *ip6, uint32(*ttl), *avecA)
	if err != nil {
		log.Fatal(err)
	}
	cfg.seuil, cfg.fenetre, cfg.ttlRepli = *seuil, *fenetre, uint32(*ttlRepli)
	cfg.etat = *etat
	for _, s := range strings.Split(*toujours, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)).To4(); ip != nil {
			cfg.toujours[ip.String()] = true
		}
	}
	if *retrait {
		if err := retirer(cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	for {
		if err := servir(cfg); err != nil {
			log.Printf("erreur : %v ; nouvel essai dans 10 s", err)
			time.Sleep(10 * time.Second)
		}
	}
}

func preparer(nom, ip4, ip6 string, ttl uint32, avecA bool) (*config, error) {
	cfg := &config{nom: strings.ToLower(strings.TrimSuffix(nom, ".")), ttl: ttl,
		ttlRepli: 120, seuil: 5, fenetre: 10 * time.Second, toujours: map[string]bool{}}
	if cfg.nom == "" || !strings.HasSuffix(cfg.nom, ".local") {
		return nil, fmt.Errorf("nom invalide %q (attendu : xxx.local)", nom)
	}
	if cfg.ipv6 = net.ParseIP(ip6); cfg.ipv6 == nil || cfg.ipv6.To4() != nil {
		return nil, fmt.Errorf("adresse IPv6 invalide %q", ip6)
	}
	v4 := net.ParseIP(ip4).To4()
	if v4 == nil {
		return nil, fmt.Errorf("adresse IPv4 invalide %q", ip4)
	}
	if avecA {
		cfg.ipv4 = v4
	}
	carte, err := carteDe(v4)
	if err != nil {
		return nil, err
	}
	cfg.carte = carte
	return cfg, nil
}

func carteDe(ip net.IP) (*net.Interface, error) {
	cartes, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range cartes {
		adrs, _ := cartes[i].Addrs()
		for _, a := range adrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return &cartes[i], nil
			}
		}
	}
	return nil, fmt.Errorf("aucune carte ne porte %s", ip)
}

func ecouter(cfg *config) (*net.UDPConn, error) {
	conn, err := net.ListenMulticastUDP("udp4", cfg.carte, groupeMDNS)
	if err != nil {
		return nil, err
	}
	if err := regler(conn); err != nil {
		log.Printf("reglage TTL multicast impossible : %v", err)
	}
	return conn, nil
}

// annoncerRetrait diffuse deux avis de retrait (TTL 0) a une seconde d'ecart.
func annoncerRetrait(conn *net.UDPConn, cfg *config) {
	adieu := reponse(cfg.nom, cfg.ipv6, nil, 0, nil)
	for i := 0; i < 2; i++ {
		conn.WriteToUDP(adieu, groupeMDNS)
		time.Sleep(time.Second)
	}
}

func retirer(cfg *config) error {
	conn, err := ecouter(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	annoncerRetrait(conn, cfg)
	log.Printf("avis de retrait envoye pour %s AAAA %s", cfg.nom, cfg.ipv6)
	return nil
}

func servir(cfg *config) error {
	conn, err := ecouter(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Efface des caches l'adresse diffusee a tous par la premiere version.
	annoncerRetrait(conn, cfg)
	log.Printf("pret : %s AAAA %s (ttl %d s) sur %s, en unicast aux sources a >= %d questions en %s",
		cfg.nom, cfg.ipv6, cfg.ttl, cfg.carte.Name, cfg.seuil, cfg.fenetre)

	r := newRepondeur(cfg)
	buf := make([]byte, 9000)
	bilan := time.Now()
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return err
			}
		} else {
			for _, e := range r.traiter(buf[:n], src, time.Now()) {
				if _, err := conn.WriteToUDP(e.data, e.dest); err != nil {
					log.Printf("envoi vers %s : %v", e.dest, err)
				}
			}
			for _, m := range r.messages {
				log.Print(m)
			}
			r.messages = r.messages[:0]
		}
		r.ecrireEtat(time.Now())
		if time.Since(bilan) >= time.Minute {
			if s := r.s; s.vues > 0 {
				log.Printf("bilan 1 min : %d questions AAAA, %d servies, %d retenues (1/s/source max), %d sous le seuil",
					s.vues, s.servies, s.retenues, s.ignorees)
			}
			r.precedent = r.s
			r.s = stats{}
			bilan = time.Now()
		}
	}
}

type envoi struct {
	data []byte
	dest *net.UDPAddr
}

type repondeur struct {
	cfg             *config
	rep             []byte
	comptes         map[string][]time.Time // questions recentes par IP source
	derniers        map[string]time.Time   // dernier envoi par adresse destination
	signales        map[string]bool        // sources deja annoncees « en boucle » au journal
	servis          map[string]int         // reponses unicast d'affilee a une source qui boucle
	dernierService  map[string]time.Time
	multicastJusqua map[string]time.Time // sources en repli multicast, et jusqu'a quand
	repRepli        []byte               // meme reponse, TTL court, pour le multicast
	vraies          map[string]time.Time // vraies AAAA publiees par d'autres, et leur expiration
	silence         bool                 // au moins une vraie AAAA valide : on se tait
	amazon          map[string]verdict   // appareils Amazon reconnus par leur MAC (cache)
	mac             func(net.IP) net.HardwareAddr
	s               stats
	precedent       stats     // bilan de la minute precedente, pour le fichier d'etat
	etatEcrit       time.Time // derniere ecriture du fichier d'etat
	messages        []string
}

func newRepondeur(cfg *config) *repondeur {
	return &repondeur{cfg: cfg, rep: reponse(cfg.nom, cfg.ipv6, cfg.ipv4, cfg.ttl, nil),
		repRepli: reponse(cfg.nom, cfg.ipv6, cfg.ipv4, cfg.ttlRepli, nil),
		comptes:  map[string][]time.Time{}, derniers: map[string]time.Time{}, signales: map[string]bool{},
		servis: map[string]int{}, dernierService: map[string]time.Time{}, multicastJusqua: map[string]time.Time{},
		vraies: map[string]time.Time{}, amazon: map[string]verdict{},
		mac: func(ip net.IP) net.HardwareAddr {
			if cfg.carte == nil {
				return nil
			}
			return macDe(ip, cfg.carte.Index)
		}}
}

// traiter decide des envois pour un paquet recu : rien pour les sources qui ne
// bouclent pas, au plus un envoi par seconde par destination (RFC 6762 §6).
func (r *repondeur) traiter(paquet []byte, src *net.UDPAddr, t time.Time) []envoi {
	m, err := lireMessage(paquet)
	if err != nil {
		return nil
	}
	if m.reponse {
		r.observer(m, src, t)
		return nil
	}
	if r.enSilence(t) {
		return nil
	}
	ok, qu := demandeAAAA(m, r.cfg.nom)
	if !ok {
		return nil
	}
	r.s.vues++
	ip := src.IP.String()
	// Une source deja reconnue (listee, produit Amazon, ou deja passee en
	// multicast) est servie des sa premiere question : ses demandes de
	// renouvellement apres un calme ne doivent pas attendre une nouvelle rafale.
	if r.estAmazon(src.IP, t) && !t.Before(r.multicastJusqua[ip]) {
		r.multicastJusqua[ip] = t.Add(dureeRepli)
	}
	connue := r.cfg.toujours[ip] || t.Before(r.multicastJusqua[ip])
	if !r.enBoucle(ip, t) && !connue {
		r.s.ignorees++
		return nil
	}
	if t.Sub(r.derniers[src.String()]) < time.Second {
		r.s.retenues++
		return nil
	}
	if len(r.derniers) > 1024 {
		r.derniers = map[string]time.Time{}
	}
	r.derniers[src.String()] = t
	r.s.servies++
	if src.Port != 5353 {
		// Requete « classique » : identifiant et question repris, TTL court.
		return []envoi{{reponse(r.cfg.nom, r.cfg.ipv6, r.cfg.ipv4, r.cfg.ttl, &requete{id: m.id}), src}}
	}
	if qu {
		// Le demandeur a lui-meme demande l'unicast : pas de repli.
		return []envoi{{r.rep, src}}
	}
	// Repli : une source qui boucle encore apres repliApres reponses unicast
	// d'affilee, ou qui REBOUCLE alors qu'on lui a deja repondu en unicast il y
	// a moins de memoire, n'accepte pas l'unicast (mesure du 26/10 : rafales de
	// 700 a 1 100 questions toutes les 2 min, contre 8 questions/min avec la
	// premiere version en multicast). On lui repond alors en multicast pendant
	// dureeRepli, comme la premiere version, avec le TTL court de repli.
	nouvelleBoucle := t.Sub(r.dernierService[ip]) > 2*r.cfg.fenetre
	if nouvelleBoucle {
		if !r.dernierService[ip].IsZero() && t.Sub(r.dernierService[ip]) < memoire && !t.Before(r.multicastJusqua[ip]) {
			r.basculer(ip, t, "reboucle malgre l'unicast")
		}
		r.servis[ip] = 0
	}
	r.dernierService[ip] = t
	r.servis[ip]++
	if r.servis[ip] > repliApres && !t.Before(r.multicastJusqua[ip]) {
		r.basculer(ip, t, fmt.Sprintf("boucle encore apres %d reponses unicast", repliApres))
	}
	if t.Before(r.multicastJusqua[ip]) {
		if t.Sub(r.derniers["multicast"]) < time.Second {
			r.s.retenues++
			return nil
		}
		r.derniers["multicast"] = t
		return []envoi{{r.repRepli, groupeMDNS}}
	}
	return []envoi{{r.rep, src}}
}

// observer suit les AAAA publiees par d'autres pour notre nom, chacune avec
// son expiration : tant qu'une seule est valide, on se tait ; son avis de
// retrait (TTL 0) l'oublie.
func (r *repondeur) observer(m *message, src *net.UDPAddr, t time.Time) {
	for _, a := range aaaaPubliees(m, r.cfg.nom) {
		ip := net.IP(a.data)
		if ip.Equal(r.cfg.ipv6) {
			continue
		}
		k := ip.String()
		if a.ttl == 0 {
			if _, ok := r.vraies[k]; ok {
				delete(r.vraies, k)
				r.messages = append(r.messages, fmt.Sprintf("vraie AAAA %s retiree par %s", k, src.IP))
			}
			continue
		}
		if _, ok := r.vraies[k]; !ok {
			r.messages = append(r.messages, fmt.Sprintf("vraie AAAA %s publiee par %s pour %s (ttl %d s)", k, src.IP, r.cfg.nom, a.ttl))
		}
		r.vraies[k] = t.Add(time.Duration(a.ttl) * time.Second)
	}
}

// enSilence oublie les vraies AAAA expirees et dit s'il en reste une valide.
func (r *repondeur) enSilence(t time.Time) bool {
	for k, fin := range r.vraies {
		if !t.Before(fin) {
			delete(r.vraies, k)
		}
	}
	avant := r.silence
	r.silence = len(r.vraies) > 0
	if avant != r.silence {
		if r.silence {
			r.messages = append(r.messages, "une vraie AAAA est valide : silence")
		} else {
			r.messages = append(r.messages, "plus aucune vraie AAAA valide : on reprend")
		}
	}
	return r.silence
}

type verdict struct {
	amazon bool
	quand  time.Time
	connu  bool // MAC trouvee dans la table ARP
}

// estAmazon dit si ip appartient a un appareil Amazon (prefixe MAC). Verdict
// garde 10 min ; une MAC absente de la table ARP est recherchee a nouveau
// apres 30 s.
func (r *repondeur) estAmazon(ip net.IP, t time.Time) bool {
	k := ip.String()
	v, ok := r.amazon[k]
	if ok && (t.Sub(v.quand) < 10*time.Minute && v.connu || t.Sub(v.quand) < 30*time.Second) {
		return v.amazon
	}
	v = verdict{quand: t}
	if mac := r.mac(ip); len(mac) == 6 {
		v.connu = true
		v.amazon = estMacAmazon(mac)
		if v.amazon && !(ok && v.amazon == r.amazon[k].amazon && r.amazon[k].connu) {
			r.messages = append(r.messages, fmt.Sprintf("%s est un produit Amazon (MAC %s) : multicast d'emblee", k, mac))
		}
	}
	if len(r.amazon) > 1024 {
		r.amazon = map[string]verdict{}
	}
	r.amazon[k] = v
	return v.amazon
}

const (
	repliApres = 10               // reponses unicast d'affilee sans effet avant le repli
	memoire    = 15 * time.Minute // une nouvelle boucle dans ce delai trahit l'unicast ignore
	dureeRepli = time.Hour        // duree du repli multicast d'une source
)

func (r *repondeur) basculer(ip string, t time.Time, pourquoi string) {
	r.multicastJusqua[ip] = t.Add(dureeRepli)
	r.messages = append(r.messages, fmt.Sprintf("%s %s : repli en multicast (ttl %d s) pour %s", ip, pourquoi, r.cfg.ttlRepli, dureeRepli))
}

// enBoucle compte la question et dit si la source a atteint le seuil.
func (r *repondeur) enBoucle(ip string, t time.Time) bool {
	h := r.comptes[ip]
	k := 0
	for _, x := range h {
		if t.Sub(x) < r.cfg.fenetre {
			h[k] = x
			k++
		}
	}
	h = append(h[:k], t)
	if len(h) > r.cfg.seuil {
		h = h[len(h)-r.cfg.seuil:]
	}
	if len(r.comptes) > 1024 {
		r.comptes = map[string][]time.Time{}
	}
	r.comptes[ip] = h
	boucle := len(h) >= r.cfg.seuil
	if boucle && !r.signales[ip] {
		r.signales[ip] = true
		r.messages = append(r.messages, fmt.Sprintf("%s pose la question en boucle (>= %d en %s)", ip, r.cfg.seuil, r.cfg.fenetre))
	}
	return boucle
}

// ecrireEtat reecrit le fichier d'etat lu par heal-stack (au plus une fois
// toutes les 15 s ; la boucle se reveille au moins toutes les 30 s). Ecriture
// dans un fichier temporaire puis renommage : jamais d'etat a moitie ecrit.
func (r *repondeur) ecrireEtat(t time.Time) {
	if r.cfg.etat == "" || t.Sub(r.etatEcrit) < 15*time.Second {
		return
	}
	r.etatEcrit = t
	var enRepli []string
	for ip, fin := range r.multicastJusqua {
		if t.Before(fin) {
			enRepli = append(enRepli, ip)
		}
	}
	e := map[string]any{
		"at":                t.Format(time.RFC3339),
		"nom":               r.cfg.nom,
		"ipv6":              r.cfg.ipv6.String(),
		"sources_multicast": enRepli,
		"silence":           r.silence,
		"minute_precedente": map[string]int{
			"questions": r.precedent.vues, "servies": r.precedent.servies,
			"retenues": r.precedent.retenues, "sous_le_seuil": r.precedent.ignorees,
		},
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	tmp := r.cfg.etat + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		os.Rename(tmp, r.cfg.etat)
	}
}
