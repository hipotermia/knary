package libknary

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func stringContains(stringA string, stringB string) bool {
	return strings.Contains(
		strings.ToLower(stringA),
		strings.ToLower(stringB),
	)
}

// map for blacklist
type blacklist struct {
	domain  string
	lastHit time.Time
}

var blacklistMap = map[int]blacklist{}
var blacklistCount = 0

func LoadBlacklist() (bool, error) {
	// load blacklist file into struct on startup
	if _, err := os.Stat(os.Getenv("BLACKLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	blklist, err := os.Open(os.Getenv("BLACKLIST_FILE"))
	defer blklist.Close()

	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}

	scanner := bufio.NewScanner(blklist)
	//count := 0
	for scanner.Scan() { // foreach blacklist item
		blacklistMap[blacklistCount] = blacklist{scanner.Text(), time.Now()} // add to struct
		blacklistCount++
	}

	Printy("Monitoring "+strconv.Itoa(blacklistCount)+" items in blacklist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(blacklistCount)+" items in blacklist")
	return true, nil
}

func CheckLastHit() bool { // this runs once a day
	if len(blacklistMap) != 0 {
		// iterate through blacklist and look for items >14 days old
		for i := range blacklistMap { // foreach blacklist item
			expiryDate := blacklistMap[i].lastHit.AddDate(0, 0, 14)

			if time.Now().After(expiryDate) { // let 'em know it's old
				go sendMsg(":wrench: Blacklist item `" + blacklistMap[i].domain + "` hasn't had a hit in >14 days. Consider removing it. Configure `BLACKLIST_ALERTING` to supress.")
				logger("INFO", "Blacklist item: "+blacklistMap[i].domain+" hasn't had a hit in >14 days. Consider removing it.")
				Printy("Blacklist item: "+blacklistMap[i].domain+" hasn't had a hit in >14 days. Consider removing it.", 1)
				return false
			}
		}

		logger("INFO", "Checked blacklist...")
		if os.Getenv("DEBUG") == "true" {
			Printy("Checked for old blacklist items", 3)
		}
	}
	return true
}

func inBlacklist(needles ...string) bool {
	for _, needle := range needles {
		for i := range blacklistMap { // foreach blacklist item
			if stringContains(needle, blacklistMap[i].domain) && !stringContains(needle, "."+blacklistMap[i].domain) {
				// matches blacklist.domain or 1.1.1.1 but not x.blacklist.domain
				updBL := blacklistMap[i]
				updBL.lastHit = time.Now() // update last hit
				blacklistMap[i] = updBL

				if os.Getenv("DEBUG") == "true" {
					Printy(blacklistMap[i].domain+" found in blacklist", 3)
				}
				return true
			}
		}
	}
	return false
}

var day = 0

func CheckTLSExpiry(domain string, config *tls.Config) (bool, error) {
	port := "443"
	// need this to make testing possible
	if os.Getenv("TLS_PORT") != "" {
		port = os.Getenv("TLS_PORT")
	}

	// tls.Dial doesn't support timeouts
	// this is another soltution: https://godoc.org/github.com/getlantern/tlsdialer#DialTimeout
	// it's probably doing something like this in the background anyway
	testTLSConn, err := net.DialTimeout("tcp", domain+":"+port, 5*time.Second)

	if err != nil {
		logger("WARNING", err.Error())
		Printy(err.Error(), 2)
		return false, err
	} else {
		defer testTLSConn.Close()
	}

	conn := tls.Client(testTLSConn, config)
	err = conn.Handshake()

	if err != nil {
		logger("WARNING", err.Error())
		Printy(err.Error(), 2)
		return false, err
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	diff := time.Until(expiry)

	if int(diff.Hours()/24) <= 10 { // if cert expires in 10 days or less
		days := int(diff.Hours() / 24)
		certMsg := "The TLS certificate for `" + domain + "` expires in " + strconv.Itoa(days) + " days."
		Printy(certMsg, 2)
		logger("WARNING", certMsg)
		go sendMsg(":lock: " + certMsg)
		//while returning false here is a bit weird we need to differentiate this code path for the tests
		return false, nil
	}

	logger("INFO", "Checked TLS expiry...")
	if os.Getenv("DEBUG") == "true" {
		Printy("Checked TLS expiry", 3)
	}

	return true, nil
}

func HeartBeat(version string) (bool, error) {
	// runs weekly (and on launch) to let people know we're alive (and show them the blacklist)
	beatMsg += "❤️ Heartbeat (v" + version + ") ❤️\n"

	// print uptime
	if day == 1 {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " day\n\n"
	} else {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " days\n\n"
	}

	// print blacklisted items
	beatMsg += strconv.Itoa(blacklistCount) + " blacklisted domains: \n"
	beatMsg += "------------------------\n"
	for i := range blacklistMap { // foreach blacklist item
		beatMsg += strings.ToLower(blacklistMap[i].domain) + "\n"
	}
	beatMsg += "------------------------\n\n"

	// print usage domains
	if os.Getenv("HTTP") == "true" {
		beatMsg += "Listening for http(s)://*." + os.Getenv("CANARY_DOMAIN") + " requests\n"
	}
	if os.Getenv("DNS") == "true" {
		beatMsg += "Listening for *.dns." + os.Getenv("CANARY_DOMAIN") + " DNS requests\n"
	}
	if os.Getenv("BURP") == "true" {
		beatMsg += "Working in collaborator compatibility mode on domain *." + os.Getenv("BURP_DOMAIN") + "\n"
	}

	go sendMsg(beatMsg)

	logger("INFO", "Sent heartbeat...")
	if os.Getenv("DEBUG") == "true" {
		Printy("Sent heartbeat message", 3)
	}

	return true, nil
}

// https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups
func SignLark(secret string, timestamp int64) (string, error) {
	//timestamp + key as sha256, then base64 encode
	stringToSign := fmt.Sprintf("%v", timestamp) + "\n" + secret

	var data []byte
	h := hmac.New(sha256.New, []byte(stringToSign))
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}
