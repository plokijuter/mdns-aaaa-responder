package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

const nomTest = "monpc.local"

var (
	fausse = net.ParseIP("fe80::aaaa")
	amazon = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 81), Port: 5353}
	t0     = time.Unix(1000, 0)
)

func questionDe(nom string, qtype, qclass uint16, qu bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = ecrireNom(b, nom)
	b = binary.BigEndian.AppendUint16(b, qtype)
	if qu {
		qclass |= bitHaut
	}
	return binary.BigEndian.AppendUint16(b, qclass)
}

func q(nom string) []byte { return questionDe(nom, typeAAAA, classIN, false) }

func repTest(t *testing.T, avecA bool) *repondeur {
	t.Helper()
	cfg, err := preparerSansCarte(avecA)
	if err != nil {
		t.Fatal(err)
	}
	r := newRepondeur(cfg)
	r.mac = func(net.IP) net.HardwareAddr { return nil } // table ARP vide par defaut
	return r
}

func preparerSansCarte(avecA bool) (*config, error) {
	cfg := &config{nom: nomTest, ipv6: fausse, ttl: 3600, ttlRepli: 120, seuil: 5, fenetre: 10 * time.Second, toujours: map[string]bool{}}
	if avecA {
		cfg.ipv4 = net.IPv4(192, 0, 2, 41).To4()
	}
	return cfg, nil
}

// boucle envoie n questions de src, espacees de pas, et rend les envois.
func boucle(r *repondeur, p []byte, src *net.UDPAddr, n int, pas time.Duration) []envoi {
	var tous []envoi
	for i := 0; i < n; i++ {
		tous = append(tous, r.traiter(p, src, t0.Add(time.Duration(i)*pas))...)
	}
	return tous
}

func relire(t *testing.T, b []byte) *message {
	t.Helper()
	m, err := lireMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUnDemandeurNormalNeVoitJamaisLaFausseAdresse(t *testing.T) {
	r := repTest(t, false)
	pc := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 32), Port: 5353}
	// Une question toutes les 3 s pendant une minute : jamais 5 en 10 s.
	if e := boucle(r, q(nomTest), pc, 20, 3*time.Second); len(e) != 0 {
		t.Fatalf("un client normal a recu %d reponses", len(e))
	}
}

func TestLaBoucleAmazonRecoitUneReponseUnicastParSeconde(t *testing.T) {
	r := repTest(t, false)
	// 3 400 questions par seconde pendant 3 s.
	e := boucle(r, q("MONPC.local"), amazon, 3*3400, time.Second/3400)
	if len(e) != 3 {
		t.Fatalf("%d reponses en 3 s, attendu 3", len(e))
	}
	for _, x := range e {
		if x.dest != amazon {
			t.Fatalf("envoi vers %s au lieu de l'unicast %s", x.dest, amazon)
		}
	}
	m := relire(t, e[0].data)
	if !m.reponse || m.id != 0 || len(m.questions) != 0 || len(m.rrs) != 1 {
		t.Fatalf("reponse inattendue %+v", m)
	}
	a := m.rrs[0]
	if a.nom != nomTest || a.rtype != typeAAAA || a.class != classIN|bitHaut || a.ttl != 3600 || !net.IP(a.data).Equal(fausse) {
		t.Fatalf("enregistrement inattendu %+v", a)
	}
	if r.s.servies != 3 || r.s.ignorees != 4 {
		t.Fatalf("stats %+v (4 questions sous le seuil attendues)", r.s)
	}
}

func TestSourceListeeServieDOffice(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	if e := r.traiter(q(nomTest), amazon, t0); len(e) != 1 || e[0].dest != amazon {
		t.Fatalf("source listee non servie : %+v", e)
	}
}

func TestRequeteClassiqueSansCacheFlushEtTTL10(t *testing.T) {
	r := repTest(t, true)
	src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 32), Port: 51234}
	r.cfg.toujours["192.0.2.32"] = true
	e := r.traiter(q(nomTest), src, t0)
	if len(e) != 1 || e[0].dest != src {
		t.Fatalf("attendu unicast vers %s : %+v", src, e)
	}
	m := relire(t, e[0].data)
	if m.id != 0x1234 || len(m.questions) != 1 || m.questions[0].nom != nomTest || m.questions[0].qtype != typeAAAA {
		t.Fatalf("id/question non repris : %+v", m)
	}
	if len(m.rrs) != 2 {
		t.Fatalf("AAAA + A attendus : %+v", m.rrs)
	}
	for _, x := range m.rrs {
		if x.class != classIN || x.ttl != 10 {
			t.Fatalf("RFC 6762 §6.7 : ni cache-flush ni TTL > 10 s en reponse classique : %+v", x)
		}
	}
	if !net.IP(m.rrs[1].data).Equal(net.IPv4(192, 0, 2, 41)) {
		t.Fatalf("A additionnel faux : %+v", m.rrs[1])
	}
}

func TestClasseVerifiee(t *testing.T) {
	for _, c := range []struct {
		classe  uint16
		attendu int
	}{{classIN, 1}, {classANY, 1}, {3 /* CH */, 0}, {4 /* HS */, 0}} {
		r := repTest(t, false)
		r.cfg.toujours["192.0.2.81"] = true
		if e := r.traiter(questionDe(nomTest, typeAAAA, c.classe, false), amazon, t0); len(e) != c.attendu {
			t.Errorf("classe %d : %d envois, attendu %d", c.classe, len(e), c.attendu)
		}
	}
}

func TestAvisDeRetraitTTL0(t *testing.T) {
	m := relire(t, reponse(nomTest, fausse, nil, 0, nil))
	if len(m.rrs) != 1 || m.rrs[0].ttl != 0 || m.rrs[0].class != classIN|bitHaut || !net.IP(m.rrs[0].data).Equal(fausse) {
		t.Fatalf("avis de retrait inattendu : %+v", m.rrs)
	}
}

func TestIgnoreLeResteDuTrafic(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	cas := map[string][]byte{
		"autre nom":         q("echoshow.local"),
		"type A":            questionDe(nomTest, typeA, classIN, false),
		"paquet tronque":    q(nomTest)[:20],
		"paquet trop court": {0, 1, 2},
	}
	// La reponse NSEC de Windows : surtout ne pas y repondre.
	nsec := q(nomTest)
	binary.BigEndian.PutUint16(nsec[2:4], 0x8400)
	cas["reponse (NSEC de Windows)"] = nsec
	// Pointeur de compression qui boucle sur lui-meme.
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], 1)
	cas["pointeur en boucle"] = append(b, 0xC0, 12, 0, 28, 0, 1)
	for nom, p := range cas {
		if e := r.traiter(p, amazon, t0); len(e) != 0 {
			t.Errorf("%s : reponse inattendue", nom)
		}
	}
}

func TestNomCompresseEtTypeANY(t *testing.T) {
	// Deux questions : la seconde pointe vers « local » de la premiere.
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], 2)
	b = ecrireNom(b, "echoshow.local")
	b = append(b, 0, 1, 0, 1)
	b = append(b, 5)
	b = append(b, "monpc"...)
	b = append(b, 0xC0, 12+9) // « local » commence apres 8 + 1 octets
	b = append(b, 0, typeANY, 0, 1)
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	if e := r.traiter(b, amazon, t0); len(e) != 1 {
		t.Fatalf("question ANY compressee non reconnue : %+v", e)
	}
}

func TestPreparerRefuseLesErreurs(t *testing.T) {
	for _, c := range [][3]string{
		{"desktop", "192.0.2.41", "fe80::1"},
		{"x.local", "pas-une-ip", "fe80::1"},
		{"x.local", "192.0.2.41", "10.0.0.1"},
	} {
		if _, err := preparer(c[0], c[1], c[2], 3600, false); err == nil {
			t.Errorf("%v accepte", c)
		}
	}
}

func compter(e []envoi, src *net.UDPAddr) (uni, multi int) {
	for _, x := range e {
		switch x.dest {
		case src:
			uni++
		case groupeMDNS:
			multi++
		}
	}
	return
}

func TestRepliSiLaBoucleContinueMalgreLUnicast(t *testing.T) {
	r := repTest(t, false)
	// 15 s de boucle continue a 100 questions/s : 10 reponses unicast, puis multicast.
	uni, multi := compter(boucle(r, q(nomTest), amazon, 15*100, 10*time.Millisecond), amazon)
	if uni != repliApres || multi != 15-repliApres {
		t.Fatalf("unicast %d (attendu %d), multicast %d (attendu %d)", uni, repliApres, multi, 15-repliApres)
	}
}

func TestRepliSiRafalesRepeteesMalgreLUnicast(t *testing.T) {
	// Le motif mesure le 26/10 avec la v2 : rafale de 3 s toutes les 2 min.
	r := repTest(t, false)
	var e []envoi
	for rafale := 0; rafale < 3; rafale++ {
		debut := t0.Add(time.Duration(rafale) * 2 * time.Minute)
		for i := 0; i < 3*300; i++ {
			e = append(e, r.traiter(q(nomTest), amazon, debut.Add(time.Duration(i)*time.Second/300))...)
		}
		uni, multi := compter(e, amazon)
		if rafale == 0 && (uni != 3 || multi != 0) {
			t.Fatalf("1re rafale : %d unicast / %d multicast, attendu 3 / 0", uni, multi)
		}
		if rafale > 0 && multi == 0 {
			t.Fatalf("rafale %d : toujours aucun multicast apres un unicast ignore", rafale+1)
		}
		e = e[:0]
	}
	if !t0.Add(4 * time.Minute).Before(r.multicastJusqua["192.0.2.81"]) {
		t.Fatal("repli multicast non memorise")
	}
	// La reponse multicast porte le TTL court de repli.
	e = nil
	for i := 0; i < 6; i++ { // petite rafale : la source redevient « en boucle »
		e = append(e, r.traiter(q(nomTest), amazon, t0.Add(6*time.Minute+time.Duration(i)*10*time.Millisecond))...)
	}
	if len(e) != 1 || e[0].dest != groupeMDNS {
		t.Fatalf("attendu multicast : %+v", e)
	}
	if ttl := relire(t, e[0].data).rrs[0].ttl; ttl != 120 {
		t.Fatalf("TTL de repli %d, attendu 120", ttl)
	}
}

func TestQUResteEnUnicastMemeEnRepli(t *testing.T) {
	r := repTest(t, false)
	r.multicastJusqua["192.0.2.81"] = t0.Add(time.Hour)
	r.cfg.toujours["192.0.2.81"] = true
	e := r.traiter(questionDe(nomTest, typeAAAA, classIN, true), amazon, t0)
	if len(e) != 1 || e[0].dest != amazon {
		t.Fatalf("question QU : unicast attendu, obtenu %+v", e)
	}
}

func TestSourceListeeAussiEnRepli(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	if _, multi := compter(boucle(r, q(nomTest), amazon, 15*100, 10*time.Millisecond), amazon); multi == 0 {
		t.Fatal("une source listee doit aussi pouvoir passer en multicast")
	}
}

func TestSilenceTemporaireSiVraieAAAA(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	autre := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 5353}
	vraie := net.ParseIP("fe80::1234")
	// Notre propre annonce et un avis TTL 0 inconnu ne changent rien.
	r.traiter(reponse(nomTest, fausse, nil, 3600, nil), autre, t0)
	r.traiter(reponse(nomTest, net.ParseIP("fe80::9"), nil, 0, nil), autre, t0)
	if len(r.traiter(q(nomTest), amazon, t0)) != 1 {
		t.Fatal("silence a tort")
	}
	// Vraie AAAA TTL 120 : silence 120 s, puis reprise.
	r.traiter(reponse(nomTest, vraie, nil, 120, nil), autre, t0.Add(10*time.Second))
	if len(r.traiter(q(nomTest), amazon, t0.Add(60*time.Second))) != 0 {
		t.Fatal("reponse pendant la vraie AAAA")
	}
	if len(r.traiter(q(nomTest), amazon, t0.Add(131*time.Second))) != 1 {
		t.Fatal("pas de reprise apres expiration du TTL de la vraie AAAA")
	}
	// Nouvelle vraie AAAA puis son avis de retrait : reprise immediate.
	r.traiter(reponse(nomTest, vraie, nil, 120, nil), autre, t0.Add(200*time.Second))
	r.traiter(reponse(nomTest, vraie, nil, 0, nil), autre, t0.Add(205*time.Second))
	if len(r.traiter(q(nomTest), amazon, t0.Add(206*time.Second))) != 1 {
		t.Fatal("pas de reprise apres l'avis de retrait de la vraie AAAA")
	}
}

func TestProduitAmazonEnMulticastDesLaPremiereQuestion(t *testing.T) {
	r := repTest(t, false)
	r.mac = func(ip net.IP) net.HardwareAddr {
		if ip.Equal(amazon.IP) {
			return net.HardwareAddr{0x90, 0x39, 0x5f, 0x00, 0x00, 0x01} // prefixe Amazon (Echo Show)
		}
		return net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01} // un PC (adresse locale)
	}
	e := r.traiter(q(nomTest), amazon, t0)
	if len(e) != 1 || e[0].dest != groupeMDNS {
		t.Fatalf("Amazon, 1re question : multicast attendu, obtenu %+v", e)
	}
	if ttl := relire(t, e[0].data).rrs[0].ttl; ttl != 120 {
		t.Fatalf("TTL %d, attendu le TTL de repli 120", ttl)
	}
	pc := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 32), Port: 5353}
	if e := r.traiter(q(nomTest), pc, t0.Add(5*time.Second)); len(e) != 0 {
		t.Fatalf("un PC non Amazon a recu la fausse adresse : %+v", e)
	}
}

func TestMacAbsenteRetombeSurLaRegleNormale(t *testing.T) {
	r := repTest(t, false) // table ARP vide
	if e := r.traiter(q(nomTest), amazon, t0); len(e) != 0 {
		t.Fatalf("sans MAC ni boucle, aucune reponse attendue : %+v", e)
	}
}

func TestSourceReconnueServieDesUneQuestionIsolee(t *testing.T) {
	r := repTest(t, false)
	r.multicastJusqua["192.0.2.81"] = t0.Add(time.Hour)
	// Demande de renouvellement isolee, apres un long calme.
	e := r.traiter(q(nomTest), amazon, t0.Add(30*time.Minute))
	if len(e) != 1 || e[0].dest != groupeMDNS {
		t.Fatalf("source en repli, question isolee : multicast attendu, obtenu %+v", e)
	}
	if e := r.traiter(q(nomTest), amazon, t0.Add(30*time.Minute+500*time.Millisecond)); len(e) != 0 {
		t.Fatal("limite de 1 envoi par seconde non respectee")
	}
}

func TestPlusieursVraiesAAAASuiviesChacune(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	autre := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 5353}
	a, b := net.ParseIP("fe80::a"), net.ParseIP("fe80::b")
	r.traiter(reponse(nomTest, a, nil, 600, nil), autre, t0)
	r.traiter(reponse(nomTest, b, nil, 600, nil), autre, t0)
	r.traiter(reponse(nomTest, b, nil, 0, nil), autre, t0.Add(time.Second)) // b retiree, a encore valide
	if e := r.traiter(q(nomTest), amazon, t0.Add(2*time.Second)); len(e) != 0 {
		t.Fatal("reprise alors que la vraie AAAA a est encore valide")
	}
	r.traiter(reponse(nomTest, a, nil, 0, nil), autre, t0.Add(3*time.Second))
	if e := r.traiter(q(nomTest), amazon, t0.Add(4*time.Second)); len(e) != 1 {
		t.Fatal("pas de reprise apres le retrait de toutes les vraies AAAA")
	}
}

func TestFichierDEtat(t *testing.T) {
	r := repTest(t, false)
	r.cfg.etat = t.TempDir() + "/etat.json"
	r.multicastJusqua["192.0.2.81"] = t0.Add(time.Hour)
	r.ecrireEtat(t0)
	b, err := os.ReadFile(r.cfg.etat)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		At      string   `json:"at"`
		Sources []string `json:"sources_multicast"`
	}
	if err := json.Unmarshal(b, &e); err != nil || e.At == "" || len(e.Sources) != 1 || e.Sources[0] != "192.0.2.81" {
		t.Fatalf("etat inattendu %s (%v)", b, err)
	}
	r.multicastJusqua["192.0.2.51"] = t0.Add(time.Hour)
	r.ecrireEtat(t0.Add(5 * time.Second)) // trop tot : pas de reecriture
	if b2, _ := os.ReadFile(r.cfg.etat); string(b2) != string(b) {
		t.Fatal("reecriture avant 15 s")
	}
}

func TestPrefixesAmazonMasques(t *testing.T) {
	for _, c := range []struct {
		mac string
		ok  bool
	}{
		{"90:39:5f:00:00:01", true},  // prefixe Echo Show (24 bits)
		{"7c:63:05:00:00:02", true},  // autre prefixe Amazon (24 bits)
		{"20:0a:0d:b3:12:34", true},  // dans 20:0A:0D:B0/28
		{"20:0a:0d:c3:12:34", false}, // juste a cote
		{"70:b3:d5:27:0a:bc", true},  // dans 70:B3:D5:27:00/36
		{"70:b3:d5:27:1a:bc", false}, // hors du /36
		{"70:b3:d5:e6:f9:99", true},  // dans 70:B3:D5:E6:F0/36
		{"02:00:00:00:00:01", false}, // un PC
	} {
		mac, _ := net.ParseMAC(c.mac)
		if estMacAmazon(mac) != c.ok {
			t.Errorf("%s : attendu %v", c.mac, c.ok)
		}
	}
}
