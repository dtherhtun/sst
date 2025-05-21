package client

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	sealsecretclient "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dtherhtun/sst/internal/types"
)

func SetupClients(kubeconfig, oldContext, newContext, ssns string) (*types.Clients, error) {
	var err error
	var oldClient, newClient *kubernetes.Clientset

	if oldContext == "" {
		oldClient, err = CreateKubernetesClient(kubeconfig)
	} else {
		oldClient, err = CreateKubernetesClientWithContext(kubeconfig, oldContext)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating client for old context: %v", err)
	}

	if newContext == "" {
		newClient, err = CreateKubernetesClient(kubeconfig)
	} else {
		newClient, err = CreateKubernetesClientWithContext(kubeconfig, newContext)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating client for new context: %v", err)
	}

	var sealedSecretsClient *sealsecretclient.Clientset
	if newContext == "" {
		sealedSecretsClient, err = CreateSealedSecretsClient(kubeconfig, "")
	} else {
		sealedSecretsClient, err = CreateSealedSecretsClient(kubeconfig, newContext)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating sealed secrets client: %v", err)
	}

	publicKey, err := FetchSealedSecretsPublicKey(newClient, ssns)
	if err != nil {
		return nil, fmt.Errorf("error fetching public key: %v", err)
	}

	return &types.Clients{
		OldClient:           oldClient,
		NewClient:           newClient,
		SealedSecretsClient: sealedSecretsClient,
		PublicKey:           publicKey,
	}, nil
}

func CreateKubernetesClientWithContext(kubeConfig string, context string) (*kubernetes.Clientset, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig}
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: context}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading kubeconfig for context %s: %v", context, err)
	}

	return kubernetes.NewForConfig(config)
}

func CreateSealedSecretsClient(kubeconfig string, context string) (*sealsecretclient.Clientset, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: context}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading kubeconfig: %v", err)
	}

	return sealsecretclient.NewForConfig(config)
}

func FetchSealedSecretsPublicKey(client *kubernetes.Clientset, namespace string) (*rsa.PublicKey, error) {
	secrets, err := client.CoreV1().Secrets(namespace).List(
		context.TODO(),
		metav1.ListOptions{
			LabelSelector: "sealedsecrets.bitnami.com/sealed-secrets-key=active",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching sealed secrets key: %v", err)
	}

	if len(secrets.Items) == 0 {
		return nil, fmt.Errorf("no sealed secrets key found in namespace %s", namespace)
	}

	var keySecret *corev1.Secret
	mostRecent := secrets.Items[0]
	for _, secret := range secrets.Items[1:] {
		if secret.CreationTimestamp.After(mostRecent.CreationTimestamp.Time) {
			mostRecent = secret
		}
	}
	keySecret = &mostRecent

	block, _ := pem.Decode(keySecret.Data["tls.crt"])
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not RSA")
	}

	return publicKey, nil
}

func CreateKubernetesClient(kubeConfig string) (*kubernetes.Clientset, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading default kubeconfig: %v", err)
	}

	return kubernetes.NewForConfig(config)
}

func GetCurrentNamespace(kubeconfig string, context string) (string, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	var config clientcmd.ClientConfig

	if context == "" {
		config = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	} else {
		configOverrides := &clientcmd.ConfigOverrides{CurrentContext: context}
		config = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	}

	namespace, _, err := config.Namespace()
	return namespace, err
}
