package main

// Regressions de la revue du 27/10/2026 (commit 637735b).

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func reponseDe(nom string, ip net.IP, ttl uint32) []byte { return reponse(nom, ip, nil, ttl, nil) }

func TestSourceHorsDuLienIgnoree(t *testing.T) {
	r := repTest(t, false)
	ailleurs := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 5353}
	r.cfg.toujours["198.51.100.5"] = true
	if e := r.traiter(q(nomTest), ailleurs, t0); len(e) != 0 || r.s.rejetes != 1 {
		t.Fatalf("question d'un autre reseau traitee : %+v, rejetes=%d", e, r.s.rejetes)
	}
}

func TestReponsesInvalidesNeFontPasTaire(t *testing.T) {
	vraie := net.ParseIP("fe80::1234")
	nx := reponseDe(nomTest, vraie, 120)
	binary.BigEndian.PutUint16(nx[2:4], 0x8403) // rcode NXDOMAIN
	op := reponseDe(nomTest, vraie, 120)
	binary.BigEndian.PutUint16(op[2:4], 0x8400|2<<11) // opcode STATUS
	for nom, c := range map[string]struct {
		p   []byte
		src *net.UDPAddr
	}{
		"port 9999":      {reponseDe(nomTest, vraie, 120), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 9999}},
		"hors du lien":   {reponseDe(nomTest, vraie, 120), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 41), Port: 5353}},
		"rcode NXDOMAIN": {nx, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 5353}},
		"opcode non nul": {op, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 5353}},
	} {
		r := repTest(t, false)
		r.cfg.toujours["192.0.2.81"] = true
		r.traiter(c.p, c.src, t0)
		if len(r.traiter(q(nomTest), amazon, t0.Add(time.Second))) != 1 {
			t.Errorf("%s : le repondeur s'est tu", nom)
		}
	}
}

func TestSilencePlafonne(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	srv := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 41), Port: 5353}
	r.traiter(reponseDe(nomTest, net.ParseIP("fe80::1234"), 0x7fffffff), srv, t0)
	if len(r.traiter(q(nomTest), amazon, t0.Add(30*time.Minute))) != 0 {
		t.Fatal("pas de silence pendant la vraie AAAA")
	}
	if len(r.traiter(q(nomTest), amazon, t0.Add(silenceMax+time.Second))) != 1 {
		t.Fatal("silence au-dela de silenceMax malgre un TTL demesure")
	}
}

func TestQuestionClassiqueANYRenvoyeeTelleQuelle(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.32"] = true
	src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 32), Port: 51234}
	e := r.traiter(questionDe("MonPC.local", typeANY, classANY, false), src, t0)
	if len(e) != 1 {
		t.Fatalf("pas de reponse : %+v", e)
	}
	m := relire(t, e[0].data)
	if len(m.questions) != 1 || m.questions[0].brut != "MonPC.local" || m.questions[0].qtype != typeANY || m.questions[0].qclass != classANY {
		t.Fatalf("question modifiee : %+v", m.questions)
	}
	if m.rrs[0].class != classIN || m.rrs[0].ttl != 10 {
		t.Fatalf("enregistrement classique : %+v", m.rrs[0])
	}
}

func TestAdresseFictiveValidee(t *testing.T) {
	for _, ip6 := range []string{"::", "::1", "ff02::1", "2001:db8::1", "fd00::1", "192.0.2.1"} {
		if _, err := preparer("x.local", "127.0.0.1", ip6, 3600, false); err == nil {
			t.Errorf("%s accepte", ip6)
		}
	}
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	for _, n := range []string{"a..local", long + ".local", "local", ".local"} {
		if nomValide(n) {
			t.Errorf("nom %q accepte", n)
		}
	}
	if !nomValide("monpc.local") {
		t.Error("nom valide refuse")
	}
}

func TestEtatBorneEtPurge(t *testing.T) {
	r := repTest(t, false)
	r.cfg.seuil = 1
	for i := 0; i < 3*maxSources; i++ {
		src := &net.UDPAddr{IP: net.IP{10, byte(i >> 16), byte(i >> 8), byte(i)}, Port: 5353}
		r.cfg.reseau = nil // toutes les sources « sur le lien » pour ce test
		r.traiter(q(nomTest), src, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if len(r.sources) > maxSources {
		t.Fatalf("%d sources suivies, plafond %d", len(r.sources), maxSources)
	}
	r.purger(t0.Add(oubliSource + time.Hour))
	if len(r.sources) != 0 {
		t.Fatalf("%d sources encore suivies apres %s de silence", len(r.sources), oubliSource)
	}
}

func TestStatistiquesExactes(t *testing.T) {
	r := repTest(t, false)
	r.mac = func(net.IP) net.HardwareAddr { return net.HardwareAddr{0x90, 0x39, 0x5f, 0, 0, 1} }
	envois := 0
	for _, d := range []byte{81, 82, 83} { // trois appareils Amazon a la meme seconde
		envois += len(r.traiter(q(nomTest), &net.UDPAddr{IP: net.IPv4(192, 0, 2, d), Port: 5353}, t0))
	}
	if envois != 1 || r.s.servies != 1 || r.s.retenues != 2 {
		t.Fatalf("envois=%d servies=%d retenues=%d, attendu 1/1/2", envois, r.s.servies, r.s.retenues)
	}
}

func TestIPv6SurLaCarteFaitTaireEtReprendVite(t *testing.T) {
	r := repTest(t, false)
	r.cfg.toujours["192.0.2.81"] = true
	ipv6 := true
	r.ipv6Carte = func() bool { return ipv6 }
	if len(r.traiter(q(nomTest), amazon, t0)) != 0 {
		t.Fatal("reponse alors que la carte porte une vraie IPv6")
	}
	ipv6 = false // NordVPN recoupe l'IPv6
	if len(r.traiter(q(nomTest), amazon, t0.Add(1500*time.Millisecond))) != 0 {
		t.Fatal("verification plus frequente que toutes les 2 s")
	}
	if len(r.traiter(q(nomTest), amazon, t0.Add(2*time.Second))) != 1 {
		t.Fatal("pas de reprise 2 s apres la disparition de l'IPv6")
	}
}

func TestReglerReussit(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer c.Close()
	if err := regler(c); err != nil {
		t.Fatalf("regler : %v", err)
	}
}

func FuzzLireMessage(f *testing.F) {
	f.Add(q(nomTest))
	f.Add(reponse(nomTest, fausse, net.IPv4(192, 0, 2, 41), 120, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := repTest(t, false)
		r.cfg.toujours["192.0.2.81"] = true
		r.traiter(b, amazon, t0) // ne doit jamais paniquer
	})
}
