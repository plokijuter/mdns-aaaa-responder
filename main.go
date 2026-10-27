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
//   - une vraie AAAA publiee pour ce nom (reponse mDNS valide, venue du lien
//     choisi) nous fait taire tant qu'au moins une est valide, 1 h au plus
//     chacune ; une IPv6 sur la carte choisie aussi ;
//   - seuls les paquets de la carte choisie comptent (Linux : IP_MULTICAST_ALL
//     coupe et carte d'arrivee verifiee ; partout : source dans son sous-reseau).
//
// Plates-formes prises en charge : Windows et Linux.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

var groupeMDNS = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

type config struct {
	nom      string
	ip4      net.IP     // adresse de ce PC sur le lien choisi
	reseau   *net.IPNet // sous-reseau de cette adresse : seules ses sources comptent
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
	vues, servies, retenues, ignorees, rejetes int
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

	if *ip4 == "" {
		log.Fatal("l'option -ip est obligatoire : adresse IPv4 de ce PC sur le reseau local (ex. -ip 192.168.1.10)")
	}
	if *macTest != "" {
		// Diagnostic de la table ARP seulement : aucune validation de l'IPv6.
		v4 := net.ParseIP(*ip4).To4()
		if v4 == nil {
			log.Fatalf("adresse IPv4 invalide %q", *ip4)
		}
		carte, _, err := carteDe(v4)
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range strings.Split(*macTest, ",") {
			mac := macDe(net.ParseIP(strings.TrimSpace(s)), carte.Index)
			fmt.Printf("%s MAC=%s amazon=%v (carte %s, index %d)\n", s, mac, estMacAmazon(mac), carte.Name, carte.Index)
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

	if *ttl > math.MaxInt32 || *ttlRepli > math.MaxInt32 {
		log.Fatalf("-ttl et -ttl-repli : au plus %d s (RFC 2181)", math.MaxInt32)
	}
	if *seuil < 1 || *fenetre <= 0 {
		log.Fatal("-seuil doit valoir au moins 1 et -fenetre etre positive")
	}
	cfg, err := preparer(*nom, *ip4, *ip6, uint32(*ttl), *avecA)
	if err != nil {
		log.Fatal(err)
	}
	cfg.seuil, cfg.fenetre, cfg.ttlRepli = *seuil, *fenetre, uint32(*ttlRepli)
	cfg.etat = *etat
	for _, s := range strings.Split(*toujours, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ip := net.ParseIP(s).To4()
		if ip == nil {
			log.Fatalf("-toujours : adresse IPv4 invalide %q", s)
		}
		cfg.toujours[ip.String()] = true
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
			// La carte a pu disparaitre, revenir ou changer d'index (VPN).
			if carte, reseau, err := carteDe(cfg.ip4); err == nil {
				cfg.carte, cfg.reseau = carte, reseau
			}
		}
	}
}

// nomValide verifie un nom DNS en .local : etiquettes de 1 a 63 octets, 253 au total.
func nomValide(nom string) bool {
	if len(nom) > 253 || !strings.HasSuffix(nom, ".local") {
		return false
	}
	for _, e := range strings.Split(nom, ".") {
		if len(e) < 1 || len(e) > 63 {
			return false
		}
	}
	return true
}

func preparer(nom, ip4, ip6 string, ttl uint32, avecA bool) (*config, error) {
	cfg := &config{nom: strings.ToLower(strings.TrimSuffix(nom, ".")), ttl: ttl,
		ttlRepli: 120, seuil: 5, fenetre: 10 * time.Second, toujours: map[string]bool{}}
	if !nomValide(cfg.nom) {
		return nil, fmt.Errorf("nom invalide %q (attendu : xxx.local, etiquettes de 1 a 63 caracteres)", nom)
	}
	cfg.ipv6 = net.ParseIP(ip6)
	if cfg.ipv6 == nil || cfg.ipv6.To4() != nil || !cfg.ipv6.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("adresse IPv6 %q refusee : il faut une adresse unicast lien-local (fe80::/10)", ip6)
	}
	if adrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range adrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(cfg.ipv6) {
				return nil, fmt.Errorf("adresse IPv6 %s deja portee par une carte de ce PC : en choisir une autre", ip6)
			}
		}
	}
	cfg.ip4 = net.ParseIP(ip4).To4()
	if cfg.ip4 == nil {
		return nil, fmt.Errorf("adresse IPv4 invalide %q", ip4)
	}
	if avecA {
		cfg.ipv4 = cfg.ip4
	}
	carte, reseau, err := carteDe(cfg.ip4)
	if err != nil {
		return nil, err
	}
	cfg.carte, cfg.reseau = carte, reseau
	return cfg, nil
}

// carteDe rend la carte qui porte ip, et le sous-reseau de cette adresse.
func carteDe(ip net.IP) (*net.Interface, *net.IPNet, error) {
	cartes, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range cartes {
		adrs, _ := cartes[i].Addrs()
		for _, a := range adrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return &cartes[i], &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("aucune carte ne porte %s", ip)
}

// ipv6SurCarte dit si la carte choisie porte deja une adresse IPv6 : Windows
// (ou Avahi) repond alors lui-meme par une vraie AAAA, on doit se taire.
func ipv6SurCarte(carte *net.Interface) bool {
	if carte == nil {
		return false
	}
	adrs, err := carte.Addrs()
	if err != nil {
		return false
	}
	for _, a := range adrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && n.IP.To16() != nil {
			return true
		}
	}
	return false
}

func ecouter(cfg *config) (*net.UDPConn, error) {
	conn, err := net.ListenMulticastUDP("udp4", cfg.carte, groupeMDNS)
	if err != nil {
		return nil, err
	}
	if err := regler(conn); err != nil {
		log.Printf("reglage du socket incomplet : %v", err)
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
	// Efface des caches une adresse diffusee avant ce demarrage.
	annoncerRetrait(conn, cfg)
	log.Printf("pret : %s AAAA %s (ttl %d s) sur %s (%s), en unicast aux sources a >= %d questions en %s",
		cfg.nom, cfg.ipv6, cfg.ttl, cfg.carte.Name, cfg.reseau, cfg.seuil, cfg.fenetre)

	r := newRepondeur(cfg)
	r.rafraichirIPv6(time.Now())
	buf := make([]byte, 9000)
	oob := make([]byte, 256)
	bilan := time.Now()
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, oobn, _, src, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return err
			}
		} else if idx, ok := carteArrivee(oob[:oobn]); ok && idx != cfg.carte.Index {
			r.s.rejetes++ // paquet arrive par une autre carte
		} else {
			for _, e := range r.traiter(buf[:n], src, time.Now()) {
				if _, err := conn.WriteToUDP(e.data, e.dest); err != nil {
					log.Printf("envoi vers %s : %v", e.dest, err)
				}
			}
		}
		r.rafraichirIPv6(time.Now())
		for _, m := range r.messages {
			log.Print(m)
		}
		r.messages = r.messages[:0]
		r.ecrireEtat(time.Now())
		if time.Since(bilan) >= time.Minute {
			if s := r.s; s.vues > 0 || s.rejetes > 0 {
				log.Printf("bilan 1 min : %d questions AAAA, %d servies, %d retenues (1/s max), %d sous le seuil, %d paquets hors lien",
					s.vues, s.servies, s.retenues, s.ignorees, s.rejetes)
			}
			r.precedent = r.s
			r.s = stats{}
			bilan = time.Now()
			r.purger(bilan)
			// La carte a-t-elle change (disparition, nouvel index) ?
			carte, _, err := carteDe(cfg.ip4)
			if err != nil || carte.Index != cfg.carte.Index {
				return fmt.Errorf("carte de %s changee ou absente", cfg.ip4)
			}
		}
	}
}

type envoi struct {
	data []byte
	dest *net.UDPAddr
}

// source : tout ce qu'on sait d'un demandeur, en un seul endroit (borne et purge).
type source struct {
	questions       []time.Time // questions recentes, au plus cfg.seuil
	vu              time.Time   // derniere question
	dernierEnvoi    time.Time   // derniere reponse qui lui a ete destinee
	signale         bool        // deja annonce « en boucle » au journal
	servis          int         // reponses unicast d'affilee pendant la boucle en cours
	dernierService  time.Time
	multicastJusqua time.Time // repli multicast en cours, jusqu'a quand
	amazon          verdict
}

type repondeur struct {
	cfg              *config
	rep              []byte
	repRepli         []byte // meme reponse, TTL court, pour le multicast
	sources          map[string]*source
	dernierMulticast time.Time
	vraies           map[string]time.Time // vraies AAAA publiees par d'autres, et leur expiration
	silence          bool                 // au moins une vraie AAAA valide : on se tait
	ipv6Locale       bool                 // la carte choisie porte une IPv6 : on se tait
	ipv6Vu           time.Time            // derniere verification de ipv6Locale
	ipv6Carte        func() bool          // lit si la carte choisie porte une IPv6
	mac              func(net.IP) net.HardwareAddr
	s                stats
	precedent        stats     // bilan de la minute precedente, pour le fichier d'etat
	etatEcrit        time.Time // derniere ecriture du fichier d'etat
	erreurEtat       string    // derniere erreur d'ecriture du fichier d'etat (journalisee une fois)
	messages         []string
}

const (
	repliApres  = 10               // reponses unicast d'affilee sans effet avant le repli
	memoire     = 15 * time.Minute // une nouvelle boucle dans ce delai trahit l'unicast ignore
	dureeRepli  = time.Hour        // duree du repli multicast d'une source
	silenceMax  = time.Hour        // une vraie AAAA ne nous fait pas taire plus longtemps sans etre redite
	oubliSource = 2 * time.Hour    // une source muette depuis aussi longtemps est oubliee
	maxSources  = 4096             // plafond global des sources suivies
	maxVraies   = 64               // plafond des vraies AAAA suivies
	ttlIP       = 255              // TTL IP de tout envoi (RFC 6762 §11 : SHOULD, pour les clients qui le verifient)
)

func newRepondeur(cfg *config) *repondeur {
	return &repondeur{cfg: cfg, rep: reponse(cfg.nom, cfg.ipv6, cfg.ipv4, cfg.ttl, nil),
		repRepli: reponse(cfg.nom, cfg.ipv6, cfg.ipv4, cfg.ttlRepli, nil),
		sources:  map[string]*source{}, vraies: map[string]time.Time{},
		ipv6Carte: func() bool { return ipv6SurCarte(cfg.carte) },
		mac: func(ip net.IP) net.HardwareAddr {
			if cfg.carte == nil {
				return nil
			}
			return macDe(ip, cfg.carte.Index)
		}}
}

// surLeLien dit si ip appartient au sous-reseau de la carte choisie.
func (r *repondeur) surLeLien(ip net.IP) bool {
	return r.cfg.reseau == nil || r.cfg.reseau.Contains(ip)
}

func (r *repondeur) source(ip string, t time.Time) *source {
	s := r.sources[ip]
	if s == nil {
		if len(r.sources) >= maxSources {
			r.purger(t)
		}
		s = &source{}
		r.sources[ip] = s
	}
	return s
}

// purger oublie les sources muettes depuis oubliSource (sauf repli en cours)
// et, au-dela du plafond, les plus anciennes ; puis les vraies AAAA expirees.
func (r *repondeur) purger(t time.Time) {
	for ip, s := range r.sources {
		if t.Sub(s.vu) > oubliSource && !t.Before(s.multicastJusqua) {
			delete(r.sources, ip)
		}
	}
	if len(r.sources) >= maxSources {
		ips := make([]string, 0, len(r.sources))
		for ip := range r.sources {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return r.sources[ips[i]].vu.Before(r.sources[ips[j]].vu) })
		for _, ip := range ips[:len(ips)-maxSources*3/4] {
			delete(r.sources, ip)
		}
	}
	for k, fin := range r.vraies {
		if !t.Before(fin) {
			delete(r.vraies, k)
		}
	}
}

// traiter decide des envois pour un paquet recu : rien pour les sources qui ne
// bouclent pas, au plus un envoi par seconde par destination (RFC 6762 §6).
func (r *repondeur) traiter(paquet []byte, src *net.UDPAddr, t time.Time) []envoi {
	if !r.surLeLien(src.IP) {
		r.s.rejetes++
		return nil
	}
	m, err := lireMessage(paquet)
	if err != nil {
		return nil
	}
	if m.reponse {
		r.observer(m, src, t)
		return nil
	}
	r.rafraichirIPv6(t)
	if m.opcode != 0 || r.enSilence(t) {
		return nil
	}
	q, ok := demandeAAAA(m, r.cfg.nom)
	if !ok {
		return nil
	}
	r.s.vues++
	ip := src.IP.String()
	s := r.source(ip, t)
	s.vu = t
	// Une source deja reconnue (listee, produit Amazon, ou deja passee en
	// multicast) est servie des sa premiere question : ses demandes de
	// renouvellement apres un calme ne doivent pas attendre une nouvelle rafale.
	if r.estAmazon(s, src.IP, t) && !t.Before(s.multicastJusqua) {
		s.multicastJusqua = t.Add(dureeRepli)
	}
	connue := r.cfg.toujours[ip] || t.Before(s.multicastJusqua)
	if !r.enBoucle(s, ip, t) && !connue {
		r.s.ignorees++
		return nil
	}
	if t.Sub(s.dernierEnvoi) < time.Second {
		r.s.retenues++
		return nil
	}
	var e []envoi
	switch {
	case src.Port != 5353:
		// Requete « classique » : identifiant et question repris, TTL court.
		e = []envoi{{reponse(r.cfg.nom, r.cfg.ipv6, r.cfg.ipv4, r.cfg.ttl, &requete{id: m.id, q: q}), src}}
	case q.unicast:
		// Le demandeur a lui-meme demande l'unicast : pas de repli.
		e = []envoi{{r.rep, src}}
	default:
		e = r.servirQM(s, ip, t, src)
	}
	if len(e) == 0 {
		r.s.retenues++
		return nil
	}
	s.dernierEnvoi = t
	r.s.servies++
	return e
}

// servirQM : question multicast (QM). Unicast d'abord ; repli multicast pour
// une source qui boucle encore apres repliApres reponses unicast d'affilee, ou
// qui REBOUCLE alors qu'on lui a deja repondu en unicast il y a moins de
// memoire : elle n'accepte pas l'unicast (mesure du 26/10 : rafales de 700 a
// 1 100 questions toutes les 2 min, contre 8 questions/min en multicast).
func (r *repondeur) servirQM(s *source, ip string, t time.Time, src *net.UDPAddr) []envoi {
	if t.Sub(s.dernierService) > 2*r.cfg.fenetre {
		if !s.dernierService.IsZero() && t.Sub(s.dernierService) < memoire && !t.Before(s.multicastJusqua) {
			r.basculer(s, ip, t, "reboucle malgre l'unicast")
		}
		s.servis = 0
	}
	s.dernierService = t
	s.servis++
	if s.servis > repliApres && !t.Before(s.multicastJusqua) {
		r.basculer(s, ip, t, fmt.Sprintf("boucle encore apres %d reponses unicast", repliApres))
	}
	if t.Before(s.multicastJusqua) {
		// Un seul multicast par seconde, toutes sources confondues.
		if t.Sub(r.dernierMulticast) < time.Second {
			return nil
		}
		r.dernierMulticast = t
		return []envoi{{r.repRepli, groupeMDNS}}
	}
	return []envoi{{r.rep, src}}
}

func (r *repondeur) basculer(s *source, ip string, t time.Time, pourquoi string) {
	s.multicastJusqua = t.Add(dureeRepli)
	r.messages = append(r.messages, fmt.Sprintf("%s %s : repli en multicast (ttl %d s) pour %s", ip, pourquoi, r.cfg.ttlRepli, dureeRepli))
}

// observer suit les AAAA publiees par d'autres pour notre nom, chacune avec
// son expiration (plafonnee a silenceMax) : tant qu'une seule est valide, on se
// tait ; son avis de retrait (TTL 0) l'oublie. Seules comptent les reponses
// mDNS valides : port source 5353, opcode et rcode nuls, source sur le lien.
func (r *repondeur) observer(m *message, src *net.UDPAddr, t time.Time) {
	if src.Port != 5353 || m.opcode != 0 || m.rcode != 0 {
		return
	}
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
			if len(r.vraies) >= maxVraies {
				continue
			}
			r.messages = append(r.messages, fmt.Sprintf("vraie AAAA %s publiee par %s pour %s (ttl %d s)", k, src.IP, r.cfg.nom, a.ttl))
		}
		duree := time.Duration(a.ttl) * time.Second
		if duree > silenceMax {
			duree = silenceMax
		}
		r.vraies[k] = t.Add(duree)
	}
}

// rafraichirIPv6 relit, au plus toutes les 2 s, si la carte choisie porte une
// IPv6. Assez souvent pour que la reprise suive de pres sa disparition : NordVPN
// recoupe l'IPv6 en 2 a 5 s, et chaque seconde de silence laisse la tempete
// repartir (revue du 27/10 : 62 s mesurees avec un controle par minute).
func (r *repondeur) rafraichirIPv6(t time.Time) {
	if !r.ipv6Vu.IsZero() && t.Sub(r.ipv6Vu) < 2*time.Second {
		return
	}
	r.ipv6Vu = t
	if v := r.ipv6Carte(); v != r.ipv6Locale {
		r.ipv6Locale = v
		r.messages = append(r.messages, fmt.Sprintf("IPv6 sur la carte choisie : %v", v))
	}
}

// enSilence oublie les vraies AAAA expirees et dit s'il faut se taire.
func (r *repondeur) enSilence(t time.Time) bool {
	for k, fin := range r.vraies {
		if !t.Before(fin) {
			delete(r.vraies, k)
		}
	}
	avant := r.silence
	r.silence = len(r.vraies) > 0 || r.ipv6Locale
	if avant != r.silence {
		if r.silence {
			r.messages = append(r.messages, "une vraie AAAA est valide (ou la carte a une IPv6) : silence")
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

// estAmazon dit si la source appartient a un appareil Amazon (prefixe MAC).
// Verdict garde 10 min ; une MAC absente de la table ARP est recherchee a
// nouveau apres 30 s.
func (r *repondeur) estAmazon(s *source, ip net.IP, t time.Time) bool {
	v := s.amazon
	if !v.quand.IsZero() && (t.Sub(v.quand) < 10*time.Minute && v.connu || t.Sub(v.quand) < 30*time.Second) {
		return v.amazon
	}
	avant := v
	v = verdict{quand: t}
	if mac := r.mac(ip); len(mac) == 6 {
		v.connu = true
		v.amazon = estMacAmazon(mac)
		if v.amazon && !(avant.connu && avant.amazon) {
			r.messages = append(r.messages, fmt.Sprintf("%s est un produit Amazon (MAC %s) : multicast d'emblee", ip, mac))
		}
	}
	s.amazon = v
	return v.amazon
}

// enBoucle compte la question et dit si la source a atteint le seuil.
func (r *repondeur) enBoucle(s *source, ip string, t time.Time) bool {
	k := 0
	for _, x := range s.questions {
		if t.Sub(x) < r.cfg.fenetre {
			s.questions[k] = x
			k++
		}
	}
	s.questions = append(s.questions[:k], t)
	if len(s.questions) > r.cfg.seuil {
		s.questions = s.questions[len(s.questions)-r.cfg.seuil:]
	}
	boucle := len(s.questions) >= r.cfg.seuil
	if boucle && !s.signale {
		s.signale = true
		r.messages = append(r.messages, fmt.Sprintf("%s pose la question en boucle (>= %d en %s)", ip, r.cfg.seuil, r.cfg.fenetre))
	}
	return boucle
}

// ecrireEtat reecrit le fichier d'etat lu par heal-stack (au plus une fois
// toutes les 15 s ; la boucle se reveille au moins toutes les 30 s). Ecriture
// dans un fichier temporaire puis renommage : jamais d'etat a moitie ecrit.
// Une erreur d'ecriture est journalisee (une fois par erreur differente).
func (r *repondeur) ecrireEtat(t time.Time) {
	if r.cfg.etat == "" || t.Sub(r.etatEcrit) < 15*time.Second {
		return
	}
	r.etatEcrit = t
	enRepli := []string{}
	for ip, s := range r.sources {
		if t.Before(s.multicastJusqua) {
			enRepli = append(enRepli, ip)
		}
	}
	sort.Strings(enRepli)
	e := map[string]any{
		"at":                t.Format(time.RFC3339),
		"nom":               r.cfg.nom,
		"ipv6":              r.cfg.ipv6.String(),
		"sources_multicast": enRepli,
		"sources_suivies":   len(r.sources),
		"silence":           r.silence,
		"minute_precedente": map[string]int{
			"questions": r.precedent.vues, "servies": r.precedent.servies,
			"retenues": r.precedent.retenues, "sous_le_seuil": r.precedent.ignorees,
			"hors_lien": r.precedent.rejetes,
		},
	}
	b, err := json.Marshal(e)
	if err == nil {
		tmp := r.cfg.etat + ".tmp"
		if err = os.WriteFile(tmp, b, 0o644); err == nil {
			err = os.Rename(tmp, r.cfg.etat)
		}
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != r.erreurEtat {
		if msg != "" {
			log.Printf("fichier d'etat %s : %v", r.cfg.etat, err)
		} else {
			log.Printf("fichier d'etat %s : ecriture retablie", r.cfg.etat)
		}
		r.erreurEtat = msg
	}
}
