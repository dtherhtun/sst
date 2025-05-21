package types

import (
	"crypto/rsa"
	"strings"
	"sync"

	sealsecretclient "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
)

type MultiFlag []string

func (f *MultiFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *MultiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type ExportMode string

const (
	ExportModeYAML   ExportMode = "yaml"
	ExportModeDirect ExportMode = "direct"
	MaxWorkers                  = 10
)

type ProcessResult struct {
	SecretName string
	Success    bool
	Skipped    bool
	Err        error
}

type SecretProcessor struct {
	NewNamespace        string
	PublicKey           *rsa.PublicKey
	ExportMode          ExportMode
	OutputDir           string
	SealedSecretsClient *sealsecretclient.Clientset
	Results             chan ProcessResult
	WG                  sync.WaitGroup
}

type Clients struct {
	OldClient           *kubernetes.Clientset
	NewClient           *kubernetes.Clientset
	SealedSecretsClient *sealsecretclient.Clientset
	PublicKey           *rsa.PublicKey
}

type Config struct {
	Kubeconfig   string
	OldContext   string
	NewContext   string
	OldNamespace string
	NewNamespace string
	ExportMode   string
	OutputDir    string
	SSNamespace  string
	SecretName   string
	FromLiterals MultiFlag
	FromFiles    MultiFlag
}
