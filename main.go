package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func main() {
	pubKey := os.Getenv("NOSTR_PUBLIC_KEY")
	if strings.HasPrefix(pubKey, "npub") {
		pubKey = bech32Decode(pubKey)
	}
	priKey := os.Getenv("NOSTR_PRIVATE_KEY")
	if strings.HasPrefix(priKey, "nsec") {
		priKey = bech32Decode(priKey)
	}
	relay := os.Getenv("NOSTR_RELAY")

	e := &Event{
		PubKey:    pubKey,
		CreatedAt: time.Now().Unix(),
		Kind:      1,
		Tags:      [][]string{},
		Content:   "プログラムから投稿してみるテスト",
	}
	err := Sign(e, priKey)
	if err != nil {
		log.Fatalf("[ERROR] failed to Sign event: %v\n", err)
	}
	tmp, _ := json.Marshal(e)
	log.Printf("[DEBUG] event: %s\n", tmp)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c, _, err := websocket.Dial(ctx, relay, nil)
	if err != nil {
		log.Fatalf("[ERROR] failed to Dial websocket connection: %v", err)
	}
	defer c.Close(websocket.StatusInternalError, "the sky is falling")

	msg := []interface{}{
		"EVENT",
		e,
	}

	err = wsjson.Write(ctx, c, msg)
	if err != nil {
		log.Fatalf("[ERROR] failed to write event: %v", err)
	}

	var v interface{}
	err = wsjson.Read(ctx, c, &v)
	if err != nil {
		log.Fatalf("[ERROR] failed to receive event from server: %v", err)
	}
	fmt.Println(v)

	c.Close(websocket.StatusNormalClosure, "")
}

func Sign(e *Event, priKey string) error {
	a := []interface{}{
		0,
		e.PubKey,
		e.CreatedAt,
		e.Kind,
		e.Tags,
		e.Content,
	}
	b, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed JSON Marshal: %w", err)
	}
	hash := sha256.Sum256(b)
	decoded, err := hex.DecodeString(priKey)
	if err != nil {
		return fmt.Errorf("failed Decode private key to hex: %w", err)
	}
	sk, _ := btcec.PrivKeyFromBytes(decoded)
	sig, err := schnorr.Sign(sk, hash[:])
	if err != nil {
		return fmt.Errorf("failed Sign: %w", err)
	}
	e.ID = hex.EncodeToString(hash[:])
	e.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

var bech32Table = [...]uint8{'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l'}
var bech32InverseTable = map[uint8]uint8{
	'q': 0,
	'p': 1,
	'z': 2,
	'r': 3,
	'y': 4,
	'9': 5,
	'x': 6,
	'8': 7,
	'g': 8,
	'f': 9,
	'2': 10,
	't': 11,
	'v': 12,
	'd': 13,
	'w': 14,
	'0': 15,
	's': 16,
	'3': 17,
	'j': 18,
	'n': 19,
	'5': 20,
	'4': 21,
	'k': 22,
	'h': 23,
	'c': 24,
	'e': 25,
	'6': 26,
	'm': 27,
	'u': 28,
	'a': 29,
	'7': 30,
	'l': 31,
}

func bech32Decode(s string) string {
	data := decodeData(removeHRPAndChecksum(s))
	return hex.EncodeToString(data)
}

func decodeData(s string) []uint8 {
	var buf uint8 = 0
	bufBits := 0
	decoded := []uint8{}
	for _, c := range s {
		v := bech32InverseTable[uint8(c)]
		if bufBits+5 > 8 {
			n := 8 - bufBits
			bufBits = 5 - n
			buf <<= n
			buf |= (v >> bufBits)
			decoded = append(decoded, buf)
			buf = v & ((1 << bufBits) - 1)
		} else {
			buf <<= 5
			buf |= v
			bufBits += 5
		}
	}
	return decoded
}

func removeHRPAndChecksum(s string) string {
	ss := strings.Split(s, "1")
	data := ss[len(ss)-1]
	return data[:len(data)-6]
}

func bech32Encode(hrp, data string) (string, error) {
	bs, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	var buf uint16 = 0
	bufBits := 0
	values := []uint8{}
	encoded := ""

	for _, b := range bs {
		buf <<= 8
		buf |= uint16(b)
		bufBits += 8
		for bufBits >= 5 {
			v := buf >> (uint16(bufBits) - 5)
			values = append(values, uint8(v))
			encoded += string(bech32Table[v])
			buf &= (1 << (uint16(bufBits) - 5)) - 1
			bufBits -= 5
		}
	}
	if bufBits != 0 {
		v := buf << (5 - uint16(bufBits))
		values = append(values, uint8(v))
		encoded += string(bech32Table[v])
	}
	log.Printf("[DEBUG] encoded: %s", encoded)
	log.Printf("[DEBUG] checksum: %s", createChecksum(hrp, values))

	return hrp + "1" + encoded + createChecksum(hrp, values), nil
}

func createChecksum(hrp string, data []uint8) string {
	values := append(hrpExpand(hrp), data...)
	log.Printf("[DEBUG] values: %v", values)
	p := polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	checksum := ""
	for i := 0; i < 6; i++ {
		v := (p >> (5 * (5 - i))) & 31
		checksum += string(bech32Table[uint8(v)])
	}
	return checksum
}

func hrpExpand(hrp string) []uint8 {
	r := make([]uint8, 0, len(hrp)*2+1)
	for _, x := range hrp {
		r = append(r, uint8(x)>>5)
	}
	r = append(r, 0)
	for _, x := range hrp {
		r = append(r, uint8(x)&31)
	}
	return r
}

var GEN = [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []uint8) uint32 {
	var chk uint32 = 1
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if ((b >> i) & 1) != 0 {
				chk ^= GEN[i]
			}
		}
	}
	return chk
}

func verifyChecksum(hrp, data string) bool {
	converted := make([]uint8, len(data))
	for i := range data {
		converted[i] = bech32InverseTable[data[i]]
	}
	return polymod(append(hrpExpand(hrp), converted...)) == 1
}
