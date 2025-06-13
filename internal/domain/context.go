package domain

import "context"

// ContextKey is a type for context keys to avoid magic strings
type ContextKey string

const (
	// ContextKeySubject is the key for the subject (user ID) in the context
	ContextKeySubject ContextKey = "sub"
	// ContextKeyCodeChallenge is the key for the PKCE code challenge in the context
	ContextKeyCodeChallenge ContextKey = "code_challenge"
	// ContextKeyCodeChallengeMethod is the key for the PKCE code challenge method in the context
	ContextKeyCodeChallengeMethod ContextKey = "code_challenge_method"
	// ContextKeyRequestID is the key for the request ID in the context
	ContextKeyRequestID ContextKey = "request_id"
	// ContextKeyRoles is the key for the user roles in the context
	ContextKeyRoles ContextKey = "roles"
	// ContextKeyTOTPVerified is the key for the TOTP verification status in the context
	ContextKeyTOTPVerified ContextKey = "totp_verified"
)

// WithSubject adds the subject (user ID) to the context
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ContextKeySubject, subject)
}

// WithCodeChallenge adds the PKCE code challenge to the context
func WithCodeChallenge(ctx context.Context, challenge string) context.Context {
	return context.WithValue(ctx, ContextKeyCodeChallenge, challenge)
}

// WithCodeChallengeMethod adds the PKCE code challenge method to the context
func WithCodeChallengeMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, ContextKeyCodeChallengeMethod, method)
}

// WithRequestID adds the request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithRoles adds the user roles to the context
func WithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, ContextKeyRoles, roles)
}

// WithTOTPVerified adds the TOTP verification status to the context
func WithTOTPVerified(ctx context.Context, verified bool) context.Context {
	return context.WithValue(ctx, ContextKeyTOTPVerified, verified)
}

// GetSubject retrieves the subject (user ID) from the context
func GetSubject(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(ContextKeySubject).(string)
	return subject, ok
}

// GetCodeChallenge retrieves the PKCE code challenge from the context
func GetCodeChallenge(ctx context.Context) (string, bool) {
	challenge, ok := ctx.Value(ContextKeyCodeChallenge).(string)
	return challenge, ok
}

// GetCodeChallengeMethod retrieves the PKCE code challenge method from the context
func GetCodeChallengeMethod(ctx context.Context) (string, bool) {
	method, ok := ctx.Value(ContextKeyCodeChallengeMethod).(string)
	return method, ok
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(ContextKeyRequestID).(string)
	return requestID, ok
}

// GetRoles retrieves the user roles from the context
func GetRoles(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(ContextKeyRoles).([]string)
	return roles, ok
}

// GetTOTPVerified retrieves the TOTP verification status from the context
func GetTOTPVerified(ctx context.Context) (bool, bool) {
	verified, ok := ctx.Value(ContextKeyTOTPVerified).(bool)
	return verified, ok
}
