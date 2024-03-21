package main

import (
	"bytes"
	"fmt"
	"github.com/pin/tftp"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"text/template"
)

// BootstrapGateway is a class that represents the whole gateway.
type BootstrapGateway struct {
	Global GlobalConfig `yaml:"global"` // Global configuration
	IPFS   IPFSConfig   `yaml:"ipfs"`   // IPFS specific config
	Boot   BootConfig   `yaml:"boot"`   // Boot loader config
}

// GlobalConfig represents the global configuration of the gateway.
type GlobalConfig struct {
	TFTPListenAddr  string `yaml:"tftp_listen_addr"`
	HTTPListenAddr  string `yaml:"http_listen_addr"`
	HTTPSListenAddr string `yaml:"https_listen_addr"`
	TLSPrivateKey   string `yaml:"tls_private_key"`
	TLSPublicCert   string `yaml:"tls_public_cert"`
}

// IPFSConfig represents configuration specific to IPFS retrieval
type IPFSConfig struct {
	IPGetCmd string `yaml:"ipget_cmd"`
	IPFSPeer string `yaml:"ipfs_peer"`
}

// BootConfig represents bootloader-specific configuration
type BootConfig struct {
	KernelCID    string `yaml:"kernel_cid"`
	InitrdCID    string `yaml:"initrd_cid"`
	LoaderCID    string `yaml:"loader_cid"`
	LoaderLibCID string `yaml:"loader_lib_cid"`
}

// tftpHandler is called for TFTP requests and acts as a simple router for different pseudopaths.
func (c BootstrapGateway) tftpHandler(filename string, w io.ReaderFrom) error {
	client := w.(tftp.OutgoingTransfer).RemoteAddr()
	log.Printf("TFTP request from %s for %s", client.String(), filename)

	// select the right handler, given the path
	if strings.HasPrefix(filename, "/ipfs/") || strings.HasPrefix(filename, "//ipfs/") {
		// This is an IPFS URL and we should treat the next part as an IPFS CID and retrieve that object
		// If we have a leading '//', replace it with '/'. This works around issues caused by syslinux
		// pathnames and prefixes.
		newfile := strings.Replace(filename, "//", "/", -1)
		log.Printf("Retrieving IPFS object: %s", newfile)
		paths := strings.Split(newfile, "/")
		cid := paths[2] // ['', 'ipfs', cid, ...]
		err := c.ipfsHandler(w, cid)
		if err != nil {
			return err
		}
		return nil
	} else if strings.HasSuffix(filename, "ldlinux.c32") {
		// The syslinux family of bootloaders rely on a c32/e64/etc library binary to exist and be readable at
		// /ldlinux.c32. This file can also be under a different prefix (configured by DHCP options). Hack
		// that by looking up a CID in the config and using that.
		cid := c.Boot.LoaderLibCID
		log.Printf("Retrieving %s using IPFS CID %s", filename, cid)
		err := c.ipfsHandler(w, cid)
		if err != nil {
			return err
		}
		return nil
	} else if strings.HasPrefix(filename, "/pxelinux.cfg/") || strings.HasSuffix(filename, "/nocloud.cfg") {
		// Some content is dynamically generated (bootloader config, post-boot config) rather than being
		// stored statically in something like IPFS. For that content, we generate it from templates.
		log.Printf("Generating content for %s from template", filename)
		b, err := c.templateHandler(filename)
		if err != nil {
			return err
		}
		w.ReadFrom(&b)
		return nil
	}

	log.Printf("Unable to handle request for path: %s", filename)
	return fmt.Errorf("Unable to handle request for %s", filename)
}

// httpHandler is called for HTTP/HTTPS requests and acts as a simple router for different pseudopaths.
func (c BootstrapGateway) httpHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s request for %s %s %s\n",
		r.Proto, r.Method, r.Host, r.URL.Path, r.URL.RawQuery)

	// only GET is currently supported
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Only HTTP GET method is allowed\n")
		log.Printf("%s requested method %s unsupported", r.Host, r.Method)
	}

	objPath := r.URL.Path
	if strings.HasSuffix(objPath, "ldlinux.c32") {
		// specific well-known object. Find the right CID so we can find it below.
		log.Printf("Asked for well-known object ldlinux.c32")
		objPath = c.Boot.LoaderLibCID
	}

	// Do everything inline for now. TODO: have this and tftpHandler call the same generic code
	if strings.HasPrefix(r.URL.Path, "/ipfs/") {
		log.Printf("Retrieving IPFS object: %s", r.URL.Path)
		newfile := strings.Replace(r.URL.Path, "//", "/", -1)
		log.Printf("Retrieving IPFS object: %s", newfile)
		paths := strings.Split(newfile, "/")
		cid := paths[2] // ['', 'ipfs', cid, ...]
		out, err := exec.Command(c.IPFS.IPGetCmd, "-o", "/dev/stdout", "--peers", c.IPFS.IPFSPeer, cid).Output()
		if err != nil {
			log.Printf("Call to ipget %s failed: %s", cid, err)
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Write(out)
	} else {
		log.Printf("Trying to generate %s from template", r.URL.Path)
		b, err := c.templateHandler(r.URL.Path)
		if err != nil {
			log.Printf("Content generation from template failed for %s: %s", r.URL.Path, err)
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Write(b.Bytes())
	}

	//w.WriteHeader(http.StatusOK)
	//w.Header().Set("Content-Type", "text/plain")
}

// ipfsHandler is an insecure and inefficient wrapper around the ipget command. It's used to help
// prototype pulling files from IPFS, given a TFTP/HTTP request. It doesn't check the input for any
// shell nasties, and reads all of the content into a buffer in memory before sending it.
func (c BootstrapGateway) ipfsHandler(w io.ReaderFrom, cid string) error {
	// TODO: change this to also grab stderr for the logs.
	out, err := exec.Command(c.IPFS.IPGetCmd, "-o", "/dev/stdout", "--peers", c.IPFS.IPFSPeer, cid).Output()
	reader := bytes.NewReader(out)

	if err != nil {
		log.Printf("Failed to exec '%s %s': %s", c.IPFS.IPGetCmd, cid, err)
		return err
	}

	log.Printf("Writing data to client")
	w.ReadFrom(reader)

	return nil
}

// templateHandler is a simple bit of code to generate some pieces of content from templates. This
// is used for things like bootloader and other config. Given this is prototype code, it's not as
// generic as it could be, but could be made to be very generic, as it is in other similar projects.
func (c BootstrapGateway) templateHandler(filename string) (bytes.Buffer, error) {
	var buf bytes.Buffer
	templateFile := ""

	if filename == "/nocloud.cfg" {
		templateFile = "nocloud.cfg.tmpl"
	} else {
		templateFile = "syslinux.cfg.tmpl"
	}

	log.Printf("Using template %s to generate content for %s", templateFile, filename)

	t, err := template.New(templateFile).Funcs(c.templateFunctions()).ParseFiles(templateFile)
	if err != nil {
		log.Printf("Failed to parse %s: %s", templateFile, err)
		return buf, err
	}

	// Blindly pass in the config file data as template inputs.
	err = t.Execute(&buf, c)
	if err != nil {
		log.Printf("Failed to execute template %s: %s", templateFile, err)
		return buf, err
	}

	//log.Printf("Writing data to client")
	//w.ReadFrom(&buf)

	return buf, nil
}

// templateFunctions returns a map of functions allowed for use within templates
func (c BootstrapGateway) templateFunctions() template.FuncMap {
	// Not sure we need anything here at the moment, but we'll add one as a placeholder
	return template.FuncMap{
		// replaceAll replaces all instances of from in src to to.
		"replaceAll": func(src string, from string, to string) string {
			return strings.Replace(src, from, to, -1)
		},
	}
}

func startListeners(c BootstrapGateway) chan error {

	errs := make(chan error)

	// Set HTTP/HTTPS handler
	http.HandleFunc("/", c.httpHandler)

	// start HTTP/HTTPS listeners
	if c.Global.HTTPListenAddr != "" {
		// HTTP configured, listen in a goroutine
		go func() {
			log.Printf("Listening for HTTP on %s", c.Global.HTTPListenAddr)
			if err := http.ListenAndServe(c.Global.HTTPListenAddr, nil); err != nil {
				errs <- err
			}
		}()
	}

	if c.Global.HTTPSListenAddr != "" {
		// HTTPS configured. Start its listener in a goroutine.
		go func() {
			log.Printf("Listening for HTTPS on %s", c.Global.HTTPSListenAddr)
			if err := http.ListenAndServeTLS(c.Global.HTTPSListenAddr,
				c.Global.TLSPublicCert, c.Global.TLSPrivateKey, nil); err != nil {
				errs <- err
			}
		}()
	}

	// start TFTP listeners
	if c.Global.TFTPListenAddr != "" {
		// TFTP configured, Start its listener in a goroutine.
		go func() {
			log.Printf("Listening for TFTP on %s", c.Global.TFTPListenAddr)
			s := tftp.NewServer(c.tftpHandler, nil)
			if err := s.ListenAndServe(c.Global.TFTPListenAddr); err != nil {
				errs <- err
			}
		}()
	}

	return errs
}

// readConfig reads a YAML config file and returns an object containing the config and methods. This
// should probably really be made into a constructory thing.
func readConfig(filename string) (c BootstrapGateway, err error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(content, &c)
	if err != nil {
		return
	}

	return
}

func main() {
	c, err := readConfig("./config.yaml")
	if err != nil {
		log.Fatal("Error reading ./config.yaml: ", err)
	}

	log.Println(c)

	errs := startListeners(c)
	select {
	case err := <-errs:
		log.Printf("Received error from listener: %s", err)
	}
}
