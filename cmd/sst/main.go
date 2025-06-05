package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/homedir"

	"github.com/dtherhtun/sst/internal/client"
	"github.com/dtherhtun/sst/internal/helpers"
	"github.com/dtherhtun/sst/internal/processor"
	"github.com/dtherhtun/sst/internal/types"
)

func main() {
	start := time.Now()
	config := parseFlags()

	currentNs := "default"
	var err error
	if config.OldContext == "" {
		currentNs, err = client.GetCurrentNamespace(config.Kubeconfig, "")
		if err != nil {
			log.Printf("Error getting current namespace: %v", err)
		}
	}

	if config.OldNamespace == "" {
		config.OldNamespace = currentNs
		fmt.Printf("Using current namespace %s as source namespace\n", config.OldNamespace)
	}

	if config.NewNamespace == "" {
		config.NewNamespace = config.OldNamespace
		fmt.Printf("Using %s as destination namespace\n", config.NewNamespace)
	}

	if config.SecretName != "" && config.OldNamespace == "" {
		log.Fatal("When specifying a secret name, you must also specify the source namespace (-src-ns)")
	}

	clients, err := client.SetupClients(config.Kubeconfig, config.OldContext, config.NewContext, config.SSNamespace)
	if err != nil {
		log.Fatalf("Error setting up clients: %v", err)
	}

	if types.ExportMode(config.ExportMode) == types.ExportModeYAML {
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			log.Fatalf("Error creating output directory: %v", err)
		}
	}

	additionalData, err := helpers.ParseAdditionalData(config.FromLiterals, config.FromFiles)
	if err != nil {
		log.Fatalf("Error parsing additional data: %v", err)
	}

	var secrets *corev1.SecretList

	if config.SecretName != "" {
		secret, err := clients.OldClient.CoreV1().Secrets(config.OldNamespace).Get(
			context.TODO(),
			config.SecretName,
			metav1.GetOptions{},
		)
		if err != nil {
			log.Fatalf("Error getting secret %s: %v", config.SecretName, err)
		}
		secrets = &corev1.SecretList{
			Items: []corev1.Secret{*secret},
		}
		fmt.Printf("Found secret %s in namespace %s (context: %s)\n",
			config.SecretName, config.OldNamespace, config.OldContext)
	} else {
		secrets, err = clients.OldClient.CoreV1().Secrets(config.OldNamespace).List(
			context.TODO(),
			metav1.ListOptions{},
		)
		if err != nil {
			log.Fatalf("Error getting secrets from old cluster: %v", err)
		}

		fmt.Printf("Found %d secrets in namespace %s (context: %s)\n",
			len(secrets.Items), config.OldNamespace, config.OldContext)
	}

	processorObj := processor.NewProcessor(
		config.NewNamespace,
		clients.PublicKey,
		types.ExportMode(config.ExportMode),
		config.OutputDir,
		clients.SealedSecretsClient,
		len(secrets.Items),
	)

	semaphore := make(chan struct{}, types.MaxWorkers)

	for i := range secrets.Items {
		secret := secrets.Items[i]

		if config.SecretName != "" && secret.Name == config.SecretName && len(additionalData) > 0 {
			if secret.Data == nil {
				secret.Data = make(map[string][]byte)
			}
			for k, v := range additionalData {
				secret.Data[k] = v
				fmt.Printf("Injecting %s into secret %s\n", k, secret.Name)
			}
		}

		processorObj.WG.Add(1)
		go func(s corev1.Secret) {
			defer processorObj.WG.Done()
			semaphore <- struct{}{}
			processor.ProcessSecret(processorObj, s)
			<-semaphore
		}(secret)
	}

	processorObj.WG.Wait()
	close(processorObj.Results)

	var successCount, skippedCount, failedCount int
	for result := range processorObj.Results {
		switch {
		case result.Skipped:
			skippedCount++
		case result.Success:
			successCount++
		default:
			failedCount++
			log.Printf("Error processing secret %s: %v", result.SecretName, result.Err)
		}
	}

	helpers.PrintSummary(
		len(secrets.Items),
		successCount,
		skippedCount,
		failedCount,
		config.OutputDir,
		config.ExportMode,
		time.Since(start),
	)
}

func parseFlags() types.Config {
	config := types.Config{}

	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&config.Kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "path to kubeconfig file")
	}
	flag.StringVar(&config.OldContext, "src-ctx", "", "Source cluster context")
	flag.StringVar(&config.NewContext, "dst-ctx", "", "Destination cluster context")
	flag.StringVar(&config.OldNamespace, "src-ns", "", "Source namespace")
	flag.StringVar(&config.NewNamespace, "dst-ns", "", "Destination namespace")
	flag.StringVar(&config.ExportMode, "export-mode", string(types.ExportModeYAML), "Export mode: 'yaml' or 'direct'")
	flag.StringVar(&config.OutputDir, "output-dir", "sealed-secrets", "Output directory for YAML files")
	flag.StringVar(&config.SSNamespace, "sealed-secret-ns", "kube-system", "Sealed secrets namespace")
	flag.StringVar(&config.SecretName, "secret-name", "", "Specific secret name to process (optional)")
	flag.Var((*types.MultiFlag)(&config.FromLiterals), "from-literal", "Key-value pairs to inject into secret (can be used multiple times)")
	flag.Var((*types.MultiFlag)(&config.FromFiles), "from-file", "Files containing key-value pairs to inject into secret (can be used multiple times)")

	flag.Parse()

	return config
}
