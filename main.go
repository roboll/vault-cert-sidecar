package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	vaddr = flag.String("vault", "", "Vault address.")
	vauth = flag.String("auth-strategy", "token", "Vault auth strategy.")

	pkibackend = flag.String("pki-backend", "", "Vault PKI backend path.")
	pkirole    = flag.String("pki-role", "kubelet", "Vault PKI role.")

	certdir   = flag.String("cert-dir", "", "Certificate storage directory.")
	hostname  = flag.String("hostname", "", "Hostname - empty triggers hostname discovery.")
	ipsan     = flag.String("ip-san", "", "IP SAN - empty triggers ip discovery.")
	localhost = flag.Bool("localhost", false, "Include localhost in IP SANs.")

	authdir = flag.String("auth-dir", "", "Auth info (token, nonce) storage directory.")
)

type VaultAuthStrategy string

const (
	AuthToken     VaultAuthStrategy = "token"
	AuthTokenFile VaultAuthStrategy = "token-file"
	AuthAWSEC2    VaultAuthStrategy = "aws-ec2"
)

func main() {
	flag.Parse()
	log.Printf("kubelet-vault-registrar starting.")

	vclient, err := newVaultClient(*vaddr)
	if err != nil {
		panic(err.Error())
	}

	if *certdir == "" {
		panic("cert-dir is required")
	}
	if err := os.MkdirAll(*certdir, 0777); err != nil {
		panic(err.Error())
	}

	if *authdir != "" {
		if err := os.MkdirAll(*authdir, 0777); err != nil {
			panic(err.Error())
		}
	}

	if *hostname == "" {
		name, err := os.Hostname()
		if err != nil {
			panic(err.Error())
		}
		hostname = &name
	}

	if *ipsan == "" {
		ip, err := externalIP()
		if err != nil {
			panic(err.Error())
		}
		ipsan = &ip
	}

	if *localhost {
		ip := *ipsan + ",localhost"
		ipsan = &ip
	}

	info, err := getAuthInfo(*authdir)
	if err != nil {
		panic(err.Error())
	}

	if err := authenticate(vclient, VaultAuthStrategy(*vauth), info); err != nil {
		panic(err.Error())
	}

	if err := writeAuthInfo(*authdir, info); err != nil {
		panic(err.Error())
	}

	go func() {
		path := fmt.Sprintf("%s/issue/%s", *pkibackend, *pkirole)
		err := maintainCerts(vclient, path, *certdir, *hostname, *ipsan)
		if err != nil {
			log.Fatal(err.Error())
		}
	}()

	<-make(chan struct{})
}

func getAuthInfo(dir string) (map[string]string, error) {
	meta := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return filepath.SkipDir
		}
		content, err := ioutil.ReadFile(dir)
		if err != nil {
			return err
		}
		meta[info.Name()] = string(content)
		return nil
	})
	return meta, err
}

func writeAuthInfo(dir string, info map[string]string) error {
	for key, val := range info {
		err := ioutil.WriteFile(filepath.Join(dir, key), []byte(val), 0600)
		if err != nil {
			return err
		}
	}
	return nil
}

func authenticate(client *vault.Client, strategy VaultAuthStrategy, info map[string]string) error {
	switch strategy {
	case AuthToken:
		if client.Token() == "" {
			return errors.New("VAULT_TOKEN not set")
		}
		return nil
	case AuthTokenFile:
		if token, ok := info["token"]; ok && token != "" {
			client.SetToken(token)
			return nil
		} else {
			return errors.New("token file not found")
		}
	case AuthAWSEC2:
		identity, err := getAWSIdentityDocument()
		if err != nil {
			return err
		}
		pkcs := strings.Replace(string(identity), "\n", "", -1)
		payload := map[string]interface{}{
			"role":  os.Getenv("VAULT_AUTH_ROLE"),
			"pkcs7": pkcs,
		}
		nonce, ok := info["nonce"]
		if ok {
			payload["nonce"] = string(nonce)
		}
		resp, err := client.Logical().Write("auth/aws-ec2/login", payload)
		if err != nil {
			return err
		}

		info["token"] = resp.Auth.ClientToken
		info["nonce"] = resp.Auth.Metadata["nonce"]

		client.SetToken(resp.Auth.ClientToken)
		go func() {
			half := (time.Duration(resp.Auth.LeaseDuration) * time.Second) / 2
			for {
				log.Printf("scheduling token renew in %s.", half)
				select {
				case <-time.After(half):
					secret, err := client.Auth().Token().RenewSelf(0)
					if err != nil {
						log.Printf("failed to renew token: %s", err)
						half = half / 2
					} else {
						half = (time.Duration(secret.Auth.LeaseDuration) * time.Second) / 2
					}
				}
			}
		}()
		return nil
	default:
		return fmt.Errorf("unsupported auth strategy: %s", strategy)
	}
}

func newVaultClient(flag string) (*vault.Client, error) {
	vconfig := vault.DefaultConfig()
	err := vconfig.ReadEnvironment()
	if err != nil {
		panic(err.Error())
	}
	if *vaddr != "" {
		vconfig.Address = *vaddr
	}
	return vault.NewClient(vconfig)
}

func maintainCerts(client *vault.Client, path string, dir string, hostname, ipsans string) error {
	secret, err := getAndWriteCerts(client, path, dir, hostname, ipsans)
	if err != nil {
		return err
	}
	half := (time.Duration(secret.LeaseDuration) * time.Second) / 2

	for {
		log.Printf("scheduling cert update after %s", half)
		select {
		case <-time.After(half):
			secret, err := getAndWriteCerts(client, path, dir, hostname, ipsans)
			if err != nil {
				return err
			}
			half = (time.Duration(secret.LeaseDuration) * time.Second) / 2
		}
	}
}

func getAndWriteCerts(client *vault.Client, path string, dir string, hostname, ipsans string) (*vault.Secret, error) {
	log.Printf("using hostname %s, ip addr %s.", hostname, ipsans)

	secret, err := client.Logical().Write(path, map[string]interface{}{
		"common_name": hostname,
		"ip_sans":     ipsans,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("got secret with ttl %s.", time.Duration(secret.LeaseDuration)*time.Second)

	cert := secret.Data["certificate"].(string)
	if err := ioutil.WriteFile(filepath.Join(dir, "cert.pem"), []byte(cert), 0600); err != nil {
		return nil, err
	}

	key := secret.Data["private_key"].(string)
	if err := ioutil.WriteFile(filepath.Join(dir, "key.pem"), []byte(key), 0600); err != nil {
		return nil, err
	}

	ca := secret.Data["ca_chain"].(string)
	if err := ioutil.WriteFile(filepath.Join(dir, "ca.pem"), []byte(ca), 0600); err != nil {
		return nil, err
	}
	return secret, nil
}

func getAWSIdentityDocument() ([]byte, error) {
	resp, err := http.Get("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}
