package jwt

import (
	"context"
	"os"
	"testing"
	"time"

	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

var (
	vaultAddr  string
	vaultToken string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "vault:1.13.3",
			ExposedPorts: []string{"8200/tcp"},
			Env: map[string]string{
				"VAULT_DEV_ROOT_TOKEN_ID":  "test-token",
				"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
			},
			WaitingFor: wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		panic(err)
	}
	defer container.Terminate(ctx)

	host, err := container.Host(ctx)
	if err != nil {
		panic(err)
	}
	port, err := container.MappedPort(ctx, "8200")
	if err != nil {
		panic(err)
	}

	vaultAddr = fmt.Sprintf("http://%s:%s", host, port.Port())
	vaultToken = "test-token"

	// Pequeno delay para garantir que o Vault está pronto para aceitar comandos
	time.Sleep(2 * time.Second)

	// Configurar o cliente Vault
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = vaultAddr
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		panic(err)
	}
	client.SetToken(vaultToken)

	// Habilitar o transit engine
	err = client.Sys().Mount("transit", &api.MountInput{
		Type:        "transit",
		Description: "Transit secrets engine for JWT signing",
	})
	if err != nil {
		panic(err)
	}

	// Criar política para permitir operações no transit
	policy := `
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`
	err = client.Sys().PutPolicy("transit-policy", policy)
	if err != nil {
		panic(err)
	}

	// Criar token com a política
	tokenCreateRequest := &api.TokenCreateRequest{
		Policies: []string{"transit-policy"},
	}
	secret, err := client.Auth().Token().Create(tokenCreateRequest)
	if err != nil {
		panic(err)
	}

	// Atualizar o token para usar o novo token com permissões
	vaultToken = secret.Auth.ClientToken
	client.SetToken(vaultToken)

	// Criar chave transit
	_, err = client.Logical().Write("transit/keys/test-key", map[string]interface{}{
		"type": "rsa-2048",
	})
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestVaultStrategy(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	config := &domain.VaultConfig{
		Address:   vaultAddr,
		Token:     vaultToken,
		MountPath: "transit",
		KeyName:   "test-key",
	}

	t.Run("new strategy", func(t *testing.T) {
		// Criar a estratégia com o cliente Vault configurado
		strategy, err := NewVaultStrategy(config, logger)
		require.NoError(t, err)
		require.NotNil(t, strategy)

		// Verificar se a estratégia foi criada corretamente
		assert.NotEmpty(t, strategy.GetKeyID())
	})

	t.Run("token durations", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		assert.Equal(t, domain.DefaultAccessTokenDuration, strategy.GetAccessDuration())
		assert.Equal(t, domain.DefaultRefreshTokenDuration, strategy.GetRefreshDuration())
	})

	t.Run("key rotation", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
			client: nil, // simula ausência de client
		}

		err := strategy.RotateKey()
		assert.Error(t, err) // Deve retornar erro se client for nil
	})

	t.Run("get public key", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		publicKey := strategy.GetPublicKey()
		assert.Nil(t, publicKey) // Should be nil because Vault is not available
	})

	t.Run("get key ID", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
			keyID:  "vault:v1",
		}

		keyID := strategy.GetKeyID()
		assert.Equal(t, "vault:v1", keyID)
	})

	t.Run("get last rotation", func(t *testing.T) {
		// Create a mock Vault strategy
		now := time.Now()
		strategy := &vaultStrategy{
			config:       config,
			logger:       logger,
			lastRotation: now,
		}

		lastRotation := strategy.GetLastRotation()
		assert.Equal(t, now, lastRotation)
	})

	t.Run("sign token", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		// Create claims
		userID := ulid.Make()
		claims := &domain.Claims{
			Roles: []string{"user"},
			RegisteredClaims: &jwt.RegisteredClaims{
				Subject:   userID.String(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ID:        ulid.Make().String(),
			},
		}

		token, err := strategy.Sign(claims)
		require.Error(t, err) // Should fail because Vault is not available
		assert.Empty(t, token)
	})
}

func getVaultStrategy(t *testing.T) *vaultStrategy {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	config := &domain.VaultConfig{
		Address:         vaultAddr,
		Token:           vaultToken,
		MountPath:       "transit",
		KeyName:         "test-key",
		AccessDuration:  time.Hour,
		RefreshDuration: 24 * time.Hour,
	}

	strategy, err := NewVaultStrategy(config, logger)
	require.NoError(t, err)
	require.NotNil(t, strategy)

	return strategy.(*vaultStrategy)
}

// mockLogicalBackend implementa a interface LogicalBackend para testes
type mockLogicalBackend struct {
	readResponse  *api.Secret
	writeResponse *api.Secret
	readErr       error
	writeErr      error
}

func (m *mockLogicalBackend) Read(path string) (*api.Secret, error) {
	return m.readResponse, m.readErr
}

func (m *mockLogicalBackend) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return m.writeResponse, m.writeErr
}
