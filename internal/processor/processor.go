package processor

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	sealsecret "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sealsecretclient "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"

	"github.com/dtherhtun/sst/internal/types"
)

func NewProcessor(newNamespace string, publicKey *rsa.PublicKey, exportMode types.ExportMode, outputDir string, sealedSecretsClient *sealsecretclient.Clientset, resultsSize int) *types.SecretProcessor {
	return &types.SecretProcessor{
		NewNamespace:        newNamespace,
		PublicKey:           publicKey,
		ExportMode:          exportMode,
		OutputDir:           outputDir,
		SealedSecretsClient: sealedSecretsClient,
		Results:             make(chan types.ProcessResult, resultsSize),
	}
}

func ProcessSecret(p *types.SecretProcessor, secret corev1.Secret) {
	if secret.Type == corev1.SecretTypeServiceAccountToken || secret.Type == "helm.sh/release.v1" {
		p.Results <- types.ProcessResult{
			SecretName: secret.Name,
			Skipped:    true,
		}
		return
	}

	cleanSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secret.Name,
			Namespace:   p.NewNamespace,
			Labels:      secret.Labels,
			Annotations: secret.Annotations,
		},
		Type: secret.Type,
		Data: secret.Data,
	}

	ss, err := sealsecret.NewSealedSecret(scheme.Codecs, p.PublicKey, cleanSecret)
	if err != nil {
		p.Results <- types.ProcessResult{
			SecretName: secret.Name,
			Err:        fmt.Errorf("error sealing secret: %v", err),
		}
		return
	}

	var processErr error
	switch p.ExportMode {
	case types.ExportModeYAML:
		processErr = exportSealedSecretToYAML(p.OutputDir, ss)
	case types.ExportModeDirect:
		processErr = createSealedSecret(p.SealedSecretsClient, p.NewNamespace, ss)
	}

	p.Results <- types.ProcessResult{
		SecretName: secret.Name,
		Success:    processErr == nil,
		Err:        processErr,
	}
}

func exportSealedSecretToYAML(outputDir string, sealedSecret *sealsecret.SealedSecret) error {
	sealedSecret.TypeMeta = metav1.TypeMeta{
		APIVersion: "bitnami.com/v1alpha1",
		Kind:       "SealedSecret",
	}

	yamlData, err := yaml.Marshal(sealedSecret)
	if err != nil {
		return fmt.Errorf("error marshaling to YAML: %v", err)
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("%s-sealed.yaml", sealedSecret.Name))
	return os.WriteFile(filename, yamlData, 0644)
}

func createSealedSecret(client *sealsecretclient.Clientset, namespace string, ss *sealsecret.SealedSecret) error {
	_, err := client.BitnamiV1alpha1().SealedSecrets(namespace).Create(
		context.TODO(),
		ss,
		metav1.CreateOptions{},
	)
	return err
}
