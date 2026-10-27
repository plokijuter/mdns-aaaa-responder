// Fichier genere depuis la base des constructeurs de Wireshark (tshark -G manuf,
// 2026-10-26) : prefixes MAC « Amazon Technologies Inc. », « Amazon.com, LLC »
// et « Blink by Amazon ». Ne pas modifier a la main (sauf prefixesAmazonMasques,
// les trois blocs plus fins que 24 bits de la meme base).

package main

// prefixesAmazon : les 24 premiers bits des adresses MAC Amazon.
var prefixesAmazon = map[uint32]bool{
	0x007147: true, 0x00BB3A: true, 0x00F361: true, 0x00FC8B: true, 0x0812A5: true, 0x0857FB: true,
	0x086AE5: true, 0x087C39: true, 0x08849D: true, 0x089115: true, 0x0891A3: true, 0x08A6BC: true,
	0x08C224: true, 0x0C43F9: true, 0x0C47C9: true, 0x0CDC91: true, 0x0CEE99: true, 0x1009F9: true,
	0x109693: true, 0x10AE60: true, 0x10BF67: true, 0x10CE02: true, 0x140AC5: true, 0x149138: true,
	0x180B1B: true, 0x1848BE: true, 0x18742E: true, 0x1C12B0: true, 0x1C4D66: true, 0x1C93C4: true,
	0x1CFE2B: true, 0x20A171: true, 0x20BEB8: true, 0x20FE00: true, 0x244CE3: true, 0x24CE33: true,
	0x2824C9: true, 0x2873F6: true, 0x28EF01: true, 0x2C71FF: true, 0x3425BE: true, 0x34AFB3: true,
	0x34D270: true, 0x38F73D: true, 0x3C5CC4: true, 0x3CE441: true, 0x40A2DB: true, 0x40A9CF: true,
	0x40B4CD: true, 0x40F6BC: true, 0x440049: true, 0x443D54: true, 0x444201: true, 0x44650D: true,
	0x446D7F: true, 0x44B4B2: true, 0x44D5CC: true, 0x4843DD: true, 0x485F2D: true, 0x48785E: true,
	0x48B423: true, 0x4C1744: true, 0x4C53FD: true, 0x4CEFC0: true, 0x5007C3: true, 0x50D45C: true,
	0x50DCE7: true, 0x50F5DA: true, 0x542B1C: true, 0x580987: true, 0x589A3E: true, 0x58A8E8: true,
	0x58E488: true, 0x5C415A: true, 0x5C8B6B: true, 0x6813F3: true, 0x6837E9: true, 0x6854FD: true,
	0x689A87: true, 0x68B691: true, 0x68DBF5: true, 0x68F63B: true, 0x6C0C9A: true, 0x6C5697: true,
	0x6C999D: true, 0x7070AA: true, 0x7458F3: true, 0x747548: true, 0x74A7EA: true, 0x74AB93: true,
	0x74C246: true, 0x74D423: true, 0x74D637: true, 0x74E20C: true, 0x74ECB2: true, 0x786C84: true,
	0x78A03F: true, 0x78E103: true, 0x7C6166: true, 0x7C6305: true, 0x7CD566: true, 0x7CEDC6: true,
	0x800CF9: true, 0x806D71: true, 0x842859: true, 0x84D6D0: true, 0x8871E5: true, 0x8C2A85: true,
	0x901195: true, 0x90235B: true, 0x90395F: true, 0x90A822: true, 0x90F82E: true, 0x943A91: true,
	0x945AFC: true, 0x98226E: true, 0x98CCF3: true, 0x9CC8E9: true, 0xA002DC: true, 0xA0D0DC: true,
	0xA0D2B1: true, 0xA402B7: true, 0xA40801: true, 0xA8CA77: true, 0xA8E621: true, 0xAC416A: true,
	0xAC63BE: true, 0xACCCFC: true, 0xB0739C: true, 0xB08BA8: true, 0xB0CFCB: true, 0xB0F7C4: true,
	0xB0FC0D: true, 0xB4107A: true, 0xB47C9C: true, 0xB4B742: true, 0xB4E454: true, 0xB85F98: true,
	0xC08D51: true, 0xC091B9: true, 0xC095CF: true, 0xC49500: true, 0xC86C3D: true, 0xCC9EA2: true,
	0xCCF735: true, 0xD4910F: true, 0xD8BE65: true, 0xD8FBD6: true, 0xDC54D7: true, 0xDC91BF: true,
	0xDCA0D0: true, 0xE0CB1D: true, 0xE0F728: true, 0xE84C4A: true, 0xE8D87E: true, 0xEC0DE4: true,
	0xEC2BEB: true, 0xEC8AC4: true, 0xECA138: true, 0xF0272D: true, 0xF02F9E: true, 0xF04F7C: true,
	0xF08173: true, 0xF0A225: true, 0xF0D2F1: true, 0xF0F0A4: true, 0xF4032A: true, 0xF854B8: true,
	0xF8FCE1: true, 0xFC492D: true, 0xFC65DE: true, 0xFCA183: true, 0xFCA667: true, 0xFCD749: true,
	0xFCE9D8: true,
}

// prefixesAmazonMasques : blocs Amazon plus fins que 24 bits (MA-M /28, MA-S /36),
// adresse sur 48 bits et longueur du prefixe.
var prefixesAmazonMasques = []struct {
	valeur uint64
	bits   uint
}{
	{0x200A0DB00000, 28}, // 20:0A:0D:B0/28
	{0x70B3D5270000, 36}, // 70:B3:D5:27:00/36
	{0x70B3D5E6F000, 36}, // 70:B3:D5:E6:F0/36
}

// estMacAmazon dit si mac appartient a un bloc Amazon.
func estMacAmazon(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	if prefixesAmazon[uint32(mac[0])<<16|uint32(mac[1])<<8|uint32(mac[2])] {
		return true
	}
	var v uint64
	for _, b := range mac {
		v = v<<8 | uint64(b)
	}
	for _, p := range prefixesAmazonMasques {
		if v>>(48-p.bits) == p.valeur>>(48-p.bits) {
			return true
		}
	}
	return false
}
