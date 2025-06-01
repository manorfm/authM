package domain

import "fmt"

type BusinessError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

type InfraError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Error interface {
	GetCode() string
	GetMessage() string
}

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = NewBusinessError("U0001", "Invalid credentials")

	// ErrInvalidClient is returned when the client is invalid
	ErrInvalidClient = NewBusinessError("U0002", "Invalid client")

	// ErrInvalidAuthorizationCode is returned when the authorization code is invalid
	ErrInvalidAuthorizationCode = NewBusinessError("U0003", "Invalid authorization code")

	// ErrAuthorizationCodeExpired is returned when the authorization code is expired
	ErrAuthorizationCodeExpired = NewBusinessError("U0004", "Authorization code expired")

	// ErrInvalidPKCE is returned when the PKCE is invalid
	ErrInvalidPKCE = NewBusinessError("U0005", "Invalid PKCE")

	// ErrInvalidUserID is returned when the user ID is invalid
	ErrInvalidUserID = NewBusinessError("U0006", "Invalid user ID")

	// ErrNotFound is returned when a user is not found
	errNotFound = func(t string) *BusinessError {
		return NewBusinessError("U0007", fmt.Sprintf("%s not found", t))
	}

	ErrUserNotFound = errNotFound("User")

	// ErrInvalid is returned when a user is invalid
	ErrInvalid = func(t string) *BusinessError {
		return NewBusinessError("U0008", fmt.Sprintf("%s is invalid", t))
	}

	ErrClientNotFound = errNotFound("Client")

	// ErrAlreadyExists is returned when a user already exists
	ErrAlreadyExists = func(t string) *BusinessError { return NewBusinessError("U0009", fmt.Sprintf("%s already exists", t)) }

	ErrClientAlreadyExists = func(t string) *BusinessError { return ErrAlreadyExists(t) }("Client")

	ErrUserAlreadyExists = func(t string) *BusinessError { return ErrAlreadyExists(t) }("User")

	// ErrInvalidScope is returned when the scope is invalid
	ErrInvalidScope = NewBusinessError("U0010", "Invalid scope")

	// ErrInvalidField is returned when the field is invalid
	ErrInvalidField = NewBusinessError("U0011", "Invalid field")

	// ErrPathNotFound is returned when the path is not found
	ErrPathNotFound = NewBusinessError("U0012", "Path parameter not found")

	// ErrInvalidRequestBody is returned when the request body is invalid
	ErrInvalidRequestBody = NewBusinessError("U0013", "Invalid request body")

	// ErrUnauthorized is returned when the user is not authenticated
	ErrUnauthorized = NewBusinessError("U0014", "Unauthorized")

	// ErrInternal is returned when there is an internal server error
	ErrInternal = NewInfraError("U0015", "Internal server error")

	// ErrFailedGenerateToken is returned when the scope is invalid
	ErrFailedGenerateToken = NewInfraError("U0016", "Failed to generate token")

	// ErrDatabaseQuery is returned when the email check fails
	ErrDatabaseQuery = NewInfraError("U0017", "Query error")

	// ErrForbidden is returned when the user is forbidden
	ErrForbidden = NewBusinessError("U0018", "Forbidden")

	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = NewBusinessError("U0019", "Invalid token")

	// ErrInvalidDuration is returned when the duration is invalid
	ErrInvalidDuration = func(message string) *BusinessError { return NewBusinessError("U0020", message) }

	// ErrTokenExpired is returned when the token is expired
	ErrTokenExpired = NewBusinessError("U0021", "Token expired")

	// ErrTokenIssuedInFuture is returned when the token is issued in the future
	ErrTokenIssuedInFuture = NewBusinessError("U0021", "Token issued in the future")

	// ErrTokenNotYetValid is returned when the token is not yet valid
	ErrTokenNotYetValid = NewBusinessError("U0022", "Token not yet valid")

	// ErrTokenNoRoles is returned when the token has no roles
	ErrTokenNoRoles = NewBusinessError("U0023", "Token has no roles")

	// ErrTokenSubjectRequired is returned when the token subject is required
	ErrTokenSubjectRequired = NewBusinessError("U0024", "Token subject is required")

	// ErrInvalidClaims is returned when the claims are invalid
	ErrInvalidClaims = NewBusinessError("U0025", "Invalid claims")

	// ErrTokenBlacklisted is returned when the token is blacklisted
	ErrTokenBlacklisted = NewBusinessError("U0026", "Token blacklisted")

	// ErrTokenGeneration is returned when the token generation fails
	ErrTokenGeneration = NewInfraError("U0027", "Failed to generate token")

	// ErrInvalidKeyConfig is returned when the key configuration is invalid
	ErrInvalidKeyConfig = NewInfraError("U0028", "Invalid key configuration")

	// ErrInvalidSigningMethod is returned when the signing method is invalid
	ErrInvalidSigningMethod = NewBusinessError("U0029", "Invalid signing method")

	// ErrInvalidSignature is returned when the signature is invalid
	ErrInvalidSignature = NewBusinessError("U0030", "Invalid signature")

	// ErrInvalidRedirectURI is returned when the redirect URI is invalid
	ErrInvalidRedirectURI = NewBusinessError("U0031", "Invalid redirect URI")

	// ErrInvalidCodeChallengeMethod is returned when the code challenge method is invalid
	ErrInvalidCodeChallengeMethod = NewBusinessError("U0032", "Invalid code challenge method")

	// ErrInvalidCodeChallenge is returned when the code challenge is invalid
	ErrInvalidCodeChallenge = NewBusinessError("U0033", "Invalid code challenge")
)

func (e *BusinessError) GetCode() string {
	return e.Code
}

func (e *BusinessError) GetMessage() string {
	return e.Message
}

func (e *InfraError) GetCode() string {
	return e.Code
}

func (e *InfraError) GetMessage() string {
	return e.Message
}

func NewBusinessError(code, message string) *BusinessError {
	return &BusinessError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}

func NewInfraError(code, message string) *InfraError {
	return &InfraError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}
