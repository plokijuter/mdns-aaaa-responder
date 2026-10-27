package main

// Lecture et ecriture minimales de messages DNS/mDNS (RFC 1035, RFC 6762) :
// juste ce qu'il faut pour reconnaitre une question AAAA, y repondre, et
// reperer une vraie adresse IPv6 publiee par quelqu'un d'autre.

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	typeA    = 1
	typeAAAA = 28
	typeANY  = 255
	classIN  = 1
	classANY = 255

	// Bit fort de la classe : dans une question, « reponse unicast souhaitee »
	// (QU) ; dans une reponse, « cache-flush » (cet enregistrement remplace tout
	// ce que le client avait en cache pour ce nom et ce type).
	bitHaut = 0x8000

	// RFC 6762 §6.7 : une reponse a une requete « classique » (port source
	// different de 5353) ne porte pas de cache-flush et un TTL d'au plus 10 s.
	ttlClassiqueMax = 10
)

type question struct {
	nom     string // en minuscules, sans point final
	brut    string // tel que recu (casse d'origine), pour le renvoyer
	qtype   uint16
	qclass  uint16 // sans le bit QU
	unicast bool   // bit QU
}

// requete : ce qu'il faut reprendre dans une reponse « classique ».
type requete struct {
	id uint16
	q  question // la question qui nous concerne, renvoyee telle quelle
}

type rr struct {
	nom   string
	rtype uint16
	class uint16 // avec le bit cache-flush
	ttl   uint32
	data  []byte
}

type message struct {
	id        uint16
	reponse   bool  // bit QR
	opcode    uint8 // 0 = requete standard
	rcode     uint8 // 0 = pas d'erreur
	questions []question
	rrs       []rr // reponses, autorite et additionnels confondus
}

var errMessage = errors.New("message DNS invalide")

// lireMessage decode un message complet : en-tete, questions et enregistrements.
func lireMessage(b []byte) (*message, error) {
	if len(b) < 12 {
		return nil, errMessage
	}
	m := &message{
		id:      binary.BigEndian.Uint16(b[0:2]),
		reponse: binary.BigEndian.Uint16(b[2:4])&0x8000 != 0,
		opcode:  uint8(binary.BigEndian.Uint16(b[2:4]) >> 11 & 0xF),
		rcode:   uint8(binary.BigEndian.Uint16(b[2:4]) & 0xF),
	}
	nq := int(binary.BigEndian.Uint16(b[4:6]))
	nrr := int(binary.BigEndian.Uint16(b[6:8])) + int(binary.BigEndian.Uint16(b[8:10])) + int(binary.BigEndian.Uint16(b[10:12]))
	pos := 12
	for i := 0; i < nq; i++ {
		nom, suite, err := lireNom(b, pos)
		if err != nil {
			return nil, err
		}
		if suite+4 > len(b) {
			return nil, errMessage
		}
		qc := binary.BigEndian.Uint16(b[suite+2 : suite+4])
		m.questions = append(m.questions, question{
			nom:     strings.ToLower(nom),
			brut:    nom,
			qtype:   binary.BigEndian.Uint16(b[suite : suite+2]),
			qclass:  qc &^ bitHaut,
			unicast: qc&bitHaut != 0,
		})
		pos = suite + 4
	}
	for i := 0; i < nrr; i++ {
		nom, suite, err := lireNom(b, pos)
		if err != nil {
			return nil, err
		}
		if suite+10 > len(b) {
			return nil, errMessage
		}
		l := int(binary.BigEndian.Uint16(b[suite+8 : suite+10]))
		if suite+10+l > len(b) {
			return nil, errMessage
		}
		m.rrs = append(m.rrs, rr{
			nom:   strings.ToLower(nom),
			rtype: binary.BigEndian.Uint16(b[suite : suite+2]),
			class: binary.BigEndian.Uint16(b[suite+2 : suite+4]),
			ttl:   binary.BigEndian.Uint32(b[suite+4 : suite+8]),
			data:  b[suite+10 : suite+10+l],
		})
		pos = suite + 10 + l
	}
	return m, nil
}

// lireNom lit un nom a la position pos, pointeurs de compression compris, et
// rend la position qui suit le nom dans le message. Le nom garde sa casse.
func lireNom(b []byte, pos int) (string, int, error) {
	var parts []string
	suite := -1
	for sauts := 0; ; sauts++ {
		if pos >= len(b) || sauts > 64 {
			return "", 0, errMessage
		}
		l := int(b[pos])
		switch {
		case l == 0:
			if suite < 0 {
				suite = pos + 1
			}
			return strings.Join(parts, "."), suite, nil
		case l&0xC0 == 0xC0:
			if pos+1 >= len(b) {
				return "", 0, errMessage
			}
			if suite < 0 {
				suite = pos + 2
			}
			pos = int(binary.BigEndian.Uint16(b[pos:pos+2]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errMessage
		default:
			if pos+1+l > len(b) {
				return "", 0, errMessage
			}
			parts = append(parts, string(b[pos+1:pos+1+l]))
			pos += 1 + l
		}
	}
}

func ecrireNom(dst []byte, nom string) []byte {
	for _, p := range strings.Split(strings.TrimSuffix(nom, "."), ".") {
		dst = append(dst, byte(len(p)))
		dst = append(dst, p...)
	}
	return append(dst, 0)
}

func ecrireRR(dst []byte, nom string, rtype uint16, flush bool, ttl uint32, rdata []byte) []byte {
	class := uint16(classIN)
	if flush {
		class |= bitHaut // enregistrement unique : remplace le cache du client
	}
	dst = ecrireNom(dst, nom)
	dst = binary.BigEndian.AppendUint16(dst, rtype)
	dst = binary.BigEndian.AppendUint16(dst, class)
	dst = binary.BigEndian.AppendUint32(dst, ttl)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(rdata)))
	return append(dst, rdata...)
}

// reponse construit la reponse AAAA (et l'A en section additionnelle si ipv4
// n'est pas nil). Pour une requete « classique » (RFC 6762 §6.7), on reprend
// l'identifiant et la question, sans cache-flush et avec un TTL d'au plus 10 s.
// ttl = 0 donne un avis de retrait (« goodbye », RFC 6762 §10.1).
func reponse(nom string, ipv6, ipv4 net.IP, ttl uint32, classique *requete) []byte {
	b := make([]byte, 12, 128)
	flush := true
	if classique != nil {
		binary.BigEndian.PutUint16(b[0:2], classique.id)
		binary.BigEndian.PutUint16(b[4:6], 1)
		flush = false
		if ttl > ttlClassiqueMax {
			ttl = ttlClassiqueMax
		}
	}
	binary.BigEndian.PutUint16(b[2:4], 0x8400) // reponse, autoritaire
	binary.BigEndian.PutUint16(b[6:8], 1)
	if ipv4 != nil {
		binary.BigEndian.PutUint16(b[10:12], 1)
	}
	if classique != nil {
		// La question est renvoyee telle qu'elle a ete posee (nom, type et
		// classe, ANY compris) : un client classique verifie la correspondance.
		qn := classique.q.brut
		if qn == "" {
			qn = nom
		}
		b = ecrireNom(b, qn)
		b = binary.BigEndian.AppendUint16(b, classique.q.qtype)
		b = binary.BigEndian.AppendUint16(b, classique.q.qclass)
	}
	b = ecrireRR(b, nom, typeAAAA, flush, ttl, ipv6.To16())
	if ipv4 != nil {
		b = ecrireRR(b, nom, typeA, flush, ttl, ipv4.To4())
	}
	return b
}

// demandeAAAA rend la question qui demande l'AAAA (ou ANY) de nom en classe
// Internet (ou ANY), s'il y en a une.
func demandeAAAA(m *message, nom string) (question, bool) {
	for _, q := range m.questions {
		if q.nom == nom && (q.qtype == typeAAAA || q.qtype == typeANY) &&
			(q.qclass == classIN || q.qclass == classANY) {
			return q, true
		}
	}
	return question{}, false
}

// aaaaPubliees rend les enregistrements AAAA de classe Internet publies pour
// nom dans une reponse (avis de retrait TTL 0 compris).
func aaaaPubliees(m *message, nom string) []rr {
	var out []rr
	for _, r := range m.rrs {
		if r.nom == nom && r.rtype == typeAAAA && r.class&^bitHaut == classIN && len(r.data) == 16 {
			out = append(out, r)
		}
	}
	return out
}
