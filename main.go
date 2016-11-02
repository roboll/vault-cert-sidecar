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
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	vaddr = flag.String("vault", "", "Vault address.")
	vauth = flag.String("auth-strategy", "token", "Vault auth strategy.")

	pkibackend = flag.String("pki-backend", "", "Vault PKI backend path.")
	pkirole    = flag.String("pki-role", "kubelet", "Vault PKI role.")
	certdir    = flag.String("cert-dir", "/var/lib/kubelet/certs", "Certificate storage dir.")

	apiserver = flag.String("apiserver", "", "Kubernetes apiserver url.")
)

type VaultAuthStrategy string

const (
	AuthToken  VaultAuthStrategy = "token"
	AuthAWSEC2 VaultAuthStrategy = "aws-ec2"
)

func main() {
	flag.Parse()
	log.Printf("kubelet-vault-registrar starting.")

	vclient, err := newVaultClient(*vaddr)
	if err != nil {
		panic(err.Error())
	}

	if err := authenticate(vclient, VaultAuthStrategy(*vauth)); err != nil {
		panic(err.Error())
	}

	if err := os.MkdirAll(*certdir, 0777); err != nil {
		panic(err.Error())
	}

	go func() {
		path := fmt.Sprintf("%s/issue/%s", *pkibackend, *pkirole)
		err := maintainCerts(vclient, path, *certdir)
		if err != nil {
			log.Fatal(err.Error())
		}
	}()

	<-make(chan struct{})
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

func authenticate(client *vault.Client, strategy VaultAuthStrategy) error {
	switch strategy {
	case AuthToken:
		if client.Token() == "" {
			return errors.New("VAULT_TOKEN not set")
		}
		return nil
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
		resp, err := client.Logical().Write("auth/aws-ec2/login", payload)
		if err != nil {
			return err
		}

		//meta["nonce"] = resp.Auth.Metadata["nonce"]
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

func maintainCerts(client *vault.Client, path string, dir string) error {
	secret, err := getAndWriteCerts(client, path, dir)
	if err != nil {
		return err
	}
	half := (time.Duration(secret.LeaseDuration) * time.Second) / 2

	for {
		log.Printf("scheduling cert update after %s", half)
		select {
		case <-time.After(half):
			secret, err := getAndWriteCerts(client, path, dir)
			if err != nil {
				return err
			}
			half = (time.Duration(secret.LeaseDuration) * time.Second) / 2
		}
	}

	return nil
}

func getAndWriteCerts(client *vault.Client, path string, dir string) (*vault.Secret, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	ip, err := externalIP()
	if err != nil {
		return nil, err
	}
	log.Printf("using hostname %s, ip addr %s.", hostname, ip)

	secret, err := client.Logical().Write(path, map[string]interface{}{
		"common_name": hostname,
		"ip_sans":     ip,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("got secret with ttl %s.", time.Duration(secret.LeaseDuration)*time.Second)

	cert := secret.Data["certificate"].(string)
	if err := ioutil.WriteFile(fmt.Sprintf("%s/cert.pem", dir), []byte(cert), 0600); err != nil {
		return nil, err
	}

	key := secret.Data["private_key"].(string)
	if err := ioutil.WriteFile(fmt.Sprintf("%s/key.pem", dir), []byte(key), 0600); err != nil {
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
