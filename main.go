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
var bench32InverseTable = map[uint8]uint8{
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
	d := extractData(s)

	var buf uint8 = 0
	bufBits := 0
	decoded := ""

	for _, c := range d {
		v := bench32InverseTable[uint8(c)]
		if bufBits+5 > 8 {
			n := 8 - bufBits
			bufBits = 5 - n
			buf <<= n
			buf |= (v >> bufBits)
			decoded += fmt.Sprintf("%02x", buf)
			buf = v & ((1 << bufBits) - 1)
		} else {
			buf <<= 5
			buf |= v
			bufBits += 5
		}
	}
	return decoded
}

func extractData(s string) string {
	ss := strings.Split(s, "1")
	data := ss[len(ss)-1]
	return data[:len(data)-6]
}
