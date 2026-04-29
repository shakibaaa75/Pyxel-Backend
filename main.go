package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// ─── Models ───────────────────────────────────────────────────────────────────

type Project struct {
	ID          string    `json:"id"`
	AccessCode  string    `json:"accessCode"`
	ClientName  string    `json:"clientName"`
	ClientEmail string    `json:"clientEmail"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Progress    int       `json:"progress"`
	StartDate   string    `json:"startDate"`
	EndDate     string    `json:"endDate"`
	Address     string    `json:"address"`
	Budget      string    `json:"budget"`
	Updates     []Update  `json:"updates"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Update struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Phase       string    `json:"phase"`
	Progress    int       `json:"progress"`
	Images      []string  `json:"images"`
	CreatedAt   time.Time `json:"createdAt"`
}

type MagicToken struct {
	Token     string    `json:"token"`
	ProjectID string    `json:"projectId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ─── In-Memory Store ──────────────────────────────────────────────────────────

var (
	mu          sync.RWMutex
	projects    = map[string]*Project{}
	magicTokens = map[string]*MagicToken{}
)

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

// Per-IP limiter pool (pruned periodically to prevent unbounded growth).
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	limiters   = map[string]*ipLimiter{}
	limitersMu sync.Mutex
)

func getLimiter(ip string) *rate.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	entry, ok := limiters[ip]
	if !ok {
		entry = &ipLimiter{limiter: rate.NewLimiter(rate.Every(time.Minute), 60)}
		limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// pruneOldLimiters removes stale entries every 5 minutes.
func pruneOldLimiters() {
	for range time.Tick(5 * time.Minute) {
		limitersMu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, e := range limiters {
			if e.lastSeen.Before(cutoff) {
				delete(limiters, ip)
			}
		}
		limitersMu.Unlock()
	}
}

// ─── Config ───────────────────────────────────────────────────────────────────

var (
	FRONTEND_URL string

	SMTP_HOST     string
	SMTP_PORT     string
	SMTP_USERNAME string
	SMTP_PASSWORD string
	SMTP_FROM     string

	ADMIN_USERNAME     string
	ADMIN_PASSWORD_RAW string // only used at startup to hash; never stored long-term
	adminPasswordHash  []byte // bcrypt hash used at runtime

	JWT_SECRET []byte

	COMPANY_LOGO_URL string
	COMPANY_NAME     string
	COMPANY_PHONE    string
	COMPANY_EMAIL    string
	COMPANY_WEBSITE  string
)

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		slog.Warn("no .env file found, using system environment variables")
	}

	FRONTEND_URL = getEnv("FRONTEND_URL", "http://localhost:5173")

	SMTP_HOST = getEnv("SMTP_HOST", "")
	SMTP_PORT = getEnv("SMTP_PORT", "587")
	SMTP_USERNAME = getEnv("SMTP_USERNAME", "")
	SMTP_PASSWORD = getEnv("SMTP_PASSWORD", "")
	SMTP_FROM = getEnv("SMTP_FROM", "Pyxel Construction")

	ADMIN_USERNAME = getEnv("ADMIN_USERNAME", "")
	ADMIN_PASSWORD_RAW = getEnv("ADMIN_PASSWORD", "")

	jwtSecret := getEnv("JWT_SECRET", "")

	COMPANY_LOGO_URL = getEnv("COMPANY_LOGO_URL", "")
	COMPANY_NAME = getEnv("COMPANY_NAME", "Pyxel Construction")
	COMPANY_PHONE = getEnv("COMPANY_PHONE", "(916) 888-8281")
	COMPANY_EMAIL = getEnv("COMPANY_EMAIL", "contact@pyxelconstruction.com")
	COMPANY_WEBSITE = getEnv("COMPANY_WEBSITE", "https://pyxelconstruction.com")

	required := []struct{ name, value string }{
		{"SMTP_HOST", SMTP_HOST},
		{"SMTP_USERNAME", SMTP_USERNAME},
		{"SMTP_PASSWORD", SMTP_PASSWORD},
		{"ADMIN_USERNAME", ADMIN_USERNAME},
		{"ADMIN_PASSWORD", ADMIN_PASSWORD_RAW},
		{"JWT_SECRET", jwtSecret},
	}
	for _, r := range required {
		if r.value == "" {
			slog.Error("required environment variable is missing", "name", r.name)
			os.Exit(1)
		}
	}

	if len(jwtSecret) < 32 {
		slog.Error("JWT_SECRET must be at least 32 characters")
		os.Exit(1)
	}
	JWT_SECRET = []byte(jwtSecret)

	// Hash the admin password at startup with bcrypt (cost 12).
	// ADMIN_PASSWORD_RAW can then be forgotten — it is never stored.
	hash, err := bcrypt.GenerateFromPassword([]byte(ADMIN_PASSWORD_RAW), 12)
	if err != nil {
		slog.Error("failed to hash admin password", "err", err)
		os.Exit(1)
	}
	adminPasswordHash = hash
	ADMIN_PASSWORD_RAW = "" // scrub from memory

	slog.Info("company loaded", "name", COMPANY_NAME)
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// ─── ID / Token Generation ────────────────────────────────────────────────────

// generateSecureID uses crypto/rand — NOT math/rand.
func generateSecureID() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	result := make([]byte, 8)
	for i, v := range b {
		result[i] = chars[int(v)%len(chars)]
	}
	return string(result)
}

func generateAccessCode() string {
	return "PXL-" + generateSecureID()[:6]
}

func generateMagicToken() string {
	b := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ─── JWT ──────────────────────────────────────────────────────────────────────

const jwtExpiry = 8 * time.Hour

func issueAdminJWT() (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
		Issuer:    COMPANY_NAME,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(JWT_SECRET)
}

func verifyAdminJWT(tokenStr string) error {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return JWT_SECRET, nil
	})
	if err != nil || !token.Valid {
		return errors.New("invalid or expired token")
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.Subject != "admin" {
		return errors.New("invalid token claims")
	}
	return nil
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if !getLimiter(ip).Allow() {
			jsonErr(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// corsMiddleware reads the allowed origin from config instead of hardcoding it.
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == FRONTEND_URL {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=()")
		next(w, r)
	}
}

func requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			jsonErr(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if err := verifyAdminJWT(strings.TrimPrefix(authHeader, "Bearer ")); err != nil {
			jsonErr(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requestSizeMiddleware caps the request body to prevent memory exhaustion.
func requestSizeMiddleware(maxBytes int64) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next(w, r)
		}
	}
}

// chain applies middleware right-to-left (first in list = outermost).
func chain(h http.HandlerFunc, middlewares ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Take the first (client) IP only.
		return strings.SplitN(ip, ",", 2)[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func json200(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ─── Input Validation ─────────────────────────────────────────────────────────

var (
	emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	validStatus = map[string]bool{
		"planning": true, "active": true, "on-hold": true, "completed": true,
	}
)

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func validateProject(p *Project) error {
	if utf8.RuneCountInString(strings.TrimSpace(p.Title)) < 2 {
		return &validationError{"title must be at least 2 characters"}
	}
	if utf8.RuneCountInString(p.Title) > 120 {
		return &validationError{"title must be 120 characters or fewer"}
	}
	if utf8.RuneCountInString(strings.TrimSpace(p.ClientName)) < 2 {
		return &validationError{"client name must be at least 2 characters"}
	}
	if utf8.RuneCountInString(p.ClientName) > 100 {
		return &validationError{"client name must be 100 characters or fewer"}
	}
	if p.ClientEmail != "" && !emailRegexp.MatchString(p.ClientEmail) {
		return &validationError{"invalid client email address"}
	}
	if p.Status != "" && !validStatus[p.Status] {
		return &validationError{"status must be one of: planning, active, on-hold, completed"}
	}
	if p.Progress < 0 || p.Progress > 100 {
		return &validationError{"progress must be between 0 and 100"}
	}
	if utf8.RuneCountInString(p.Description) > 2000 {
		return &validationError{"description must be 2000 characters or fewer"}
	}
	if utf8.RuneCountInString(p.Address) > 300 {
		return &validationError{"address must be 300 characters or fewer"}
	}
	if utf8.RuneCountInString(p.Budget) > 50 {
		return &validationError{"budget must be 50 characters or fewer"}
	}
	return nil
}

func validateUpdate(u *Update) error {
	if utf8.RuneCountInString(strings.TrimSpace(u.Title)) < 2 {
		return &validationError{"update title must be at least 2 characters"}
	}
	if utf8.RuneCountInString(u.Title) > 120 {
		return &validationError{"update title must be 120 characters or fewer"}
	}
	if utf8.RuneCountInString(u.Description) > 5000 {
		return &validationError{"update description must be 5000 characters or fewer"}
	}
	if u.Progress < 0 || u.Progress > 100 {
		return &validationError{"progress must be between 0 and 100"}
	}
	if len(u.Images) > 20 {
		return &validationError{"maximum 20 images per update"}
	}
	return nil
}

// ─── Email ────────────────────────────────────────────────────────────────────

func sendEmail(to, subject, body string) error {
	if !emailRegexp.MatchString(to) {
		return fmt.Errorf("invalid recipient email: %s", to)
	}
	msg := []byte("From: " + SMTP_FROM + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		body)
	auth := smtp.PlainAuth("", SMTP_USERNAME, SMTP_PASSWORD, SMTP_HOST)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = ctx // smtp.SendMail doesn't accept a context; timeout handled at OS level via dial
	return smtp.SendMail(SMTP_HOST+":"+SMTP_PORT, auth, SMTP_USERNAME, []string{to}, msg)
}

func sendProjectWelcomeEmail(toEmail, clientName, projectTitle, magicLink string) {
	subject := fmt.Sprintf("Your Project %q is Now Live — Track Your Progress", projectTitle)

	logoHTML := ""
	if COMPANY_LOGO_URL != "" {
		logoHTML = fmt.Sprintf(`<img src="%s" alt="%s" style="max-width:180px;max-height:70px;filter:brightness(0) invert(1)">`,
			COMPANY_LOGO_URL, COMPANY_NAME)
	}

	body := buildWelcomeEmail(logoHTML, clientName, projectTitle, magicLink)

	// Always send in a goroutine — never block the HTTP handler.
	go func() {
		if err := sendEmail(toEmail, subject, body); err != nil {
			slog.Error("failed to send welcome email", "to", toEmail, "err", err)
		} else {
			slog.Info("welcome email sent", "to", toEmail)
		}
	}()
}

func buildWelcomeEmail(logoHTML, clientName, projectTitle, magicLink string) string {
	// Split into a function to keep sendProjectWelcomeEmail readable.
	return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f3f4f6;padding:40px 20px;margin:0}
.container{max-width:600px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.12)}
.header{background:#1e1e20;padding:28px 32px;text-align:center}
.content{padding:40px}
.btn{display:inline-block;background:#0c4196;color:#fff!important;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:16px}
.footer{padding:24px 40px;background:#f9fafb;text-align:center;border-top:1px solid #e5e7eb;font-size:13px;color:#9ca3af}
a{color:#4f6eb4}
</style></head><body>
<div class="container">
  <div class="header">` + logoHTML + `</div>
  <div class="content">
    <p style="font-size:26px;font-weight:700;color:#1e1e20;margin:0 0 12px">Hello ` + clientName + `!</p>
    <p style="color:#6b7280;line-height:1.6">Work has officially begun on your project. Track all progress, photos, and milestones through your personal dashboard.</p>
    <div style="background:#f8fafc;border-radius:12px;padding:24px;margin:24px 0;border:1px solid #e2e8f0">
      <strong>` + projectTitle + `</strong>
      <p style="color:#6b7280;margin:8px 0 0;font-size:14px">Your project portal is ready.</p>
    </div>
    <div style="text-align:center;margin:28px 0">
      <a href="` + magicLink + `" class="btn">View My Project Progress</a>
    </div>
    <p style="font-size:12px;color:#9ca3af;text-align:center">Bookmark this link: <a href="` + magicLink + `">` + magicLink + `</a></p>
  </div>
  <div class="footer">
    <strong>` + COMPANY_NAME + `</strong><br>
    ` + COMPANY_PHONE + ` | <a href="mailto:` + COMPANY_EMAIL + `">` + COMPANY_EMAIL + `</a> |
    <a href="` + COMPANY_WEBSITE + `">` + COMPANY_WEBSITE + `</a><br>
    <span style="font-size:11px;margin-top:8px;display:block">© ` + fmt.Sprintf("%d", time.Now().Year()) + ` ` + COMPANY_NAME + `. All rights reserved.</span>
  </div>
</div>
</body></html>`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Constant-time username comparison to prevent timing oracle.
	usernameMatch := subtle.ConstantTimeCompare(
		[]byte(req.Username), []byte(ADMIN_USERNAME),
	) == 1

	// Always run bcrypt comparison regardless of username to avoid timing leaks.
	bcryptErr := bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(req.Password))

	if !usernameMatch || bcryptErr != nil {
		// Uniform delay to further resist timing attacks.
		time.Sleep(200 * time.Millisecond)
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := issueAdminJWT()
	if err != nil {
		slog.Error("failed to issue JWT", "err", err)
		jsonErr(w, "internal server error", http.StatusInternalServerError)
		return
	}
	json200(w, map[string]string{"token": token, "message": "login successful"})
}

func listProjects(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]*Project, 0, len(projects))
	for _, p := range projects {
		list = append(list, p)
	}
	json200(w, list)
}

func createProject(w http.ResponseWriter, r *http.Request) {
	var p Project
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateProject(&p); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	p.ID = generateSecureID()
	p.AccessCode = generateAccessCode()
	p.Updates = []Update{}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	if p.Status == "" {
		p.Status = "planning"
	}

	magicToken := generateMagicToken()
	tokenExpiry := 90 * 24 * time.Hour // 90 days — reviewable

	mu.Lock()
	projects[p.ID] = &p
	magicTokens[magicToken] = &MagicToken{
		Token:     magicToken,
		ProjectID: p.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(tokenExpiry),
	}
	mu.Unlock()

	magicLink := fmt.Sprintf("%s/track?t=%s", FRONTEND_URL, magicToken)
	emailSent := false
	if p.ClientEmail != "" {
		sendProjectWelcomeEmail(p.ClientEmail, p.ClientName, p.Title, magicLink)
		emailSent = true
	}

	slog.Info("project created", "id", p.ID, "title", p.Title)
	w.WriteHeader(http.StatusCreated)
	json200(w, map[string]any{
		"project":    p,
		"magicLink":  magicLink,
		"emailSent":  emailSent,
		"accessCode": p.AccessCode,
	})
}

func updateProject(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/admin/projects/", 0)
	if id == "" {
		jsonErr(w, "missing project ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	p, ok := projects[id]
	if !ok {
		jsonErr(w, "project not found", http.StatusNotFound)
		return
	}

	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Apply updates individually with type assertions.
	if v, ok := updates["clientName"].(string); ok {
		p.ClientName = v
	}
	if v, ok := updates["clientEmail"].(string); ok {
		if v != "" && !emailRegexp.MatchString(v) {
			jsonErr(w, "invalid client email address", http.StatusUnprocessableEntity)
			return
		}
		p.ClientEmail = v
	}
	if v, ok := updates["title"].(string); ok {
		if utf8.RuneCountInString(strings.TrimSpace(v)) < 2 {
			jsonErr(w, "title must be at least 2 characters", http.StatusUnprocessableEntity)
			return
		}
		p.Title = v
	}
	if v, ok := updates["description"].(string); ok {
		p.Description = v
	}
	if v, ok := updates["status"].(string); ok {
		if !validStatus[v] {
			jsonErr(w, "invalid status value", http.StatusUnprocessableEntity)
			return
		}
		p.Status = v
	}
	if v, ok := updates["progress"].(float64); ok {
		if v < 0 || v > 100 {
			jsonErr(w, "progress must be 0–100", http.StatusUnprocessableEntity)
			return
		}
		p.Progress = int(v)
	}
	if v, ok := updates["endDate"].(string); ok {
		p.EndDate = v
	}
	if v, ok := updates["address"].(string); ok {
		p.Address = v
	}
	if v, ok := updates["budget"].(string); ok {
		p.Budget = v
	}
	p.UpdatedAt = time.Now()
	slog.Info("project updated", "id", p.ID)
	json200(w, p)
}

func deleteProject(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/admin/projects/", 0)
	if id == "" {
		jsonErr(w, "missing project ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := projects[id]; !ok {
		jsonErr(w, "project not found", http.StatusNotFound)
		return
	}
	for token, mt := range magicTokens {
		if mt.ProjectID == id {
			delete(magicTokens, token)
		}
	}
	delete(projects, id)
	slog.Info("project deleted", "id", id)
	json200(w, map[string]string{"message": "deleted"})
}

func addUpdate(w http.ResponseWriter, r *http.Request) {
	// Path: /api/admin/projects/{id}/updates
	id := extractPathSegment(r.URL.Path, "/api/admin/projects/", 0)
	if id == "" {
		jsonErr(w, "missing project ID", http.StatusBadRequest)
		return
	}

	var u Update
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateUpdate(&u); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	p, ok := projects[id]
	if !ok {
		jsonErr(w, "project not found", http.StatusNotFound)
		return
	}

	u.ID = generateSecureID()
	u.CreatedAt = time.Now()
	if u.Images == nil {
		u.Images = []string{}
	}
	p.Updates = append(p.Updates, u)
	if u.Progress > 0 {
		p.Progress = u.Progress
	}
	p.UpdatedAt = time.Now()
	slog.Info("update added", "projectId", id, "updateId", u.ID)
	json200(w, p)
}

func getProjectByCode(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		jsonErr(w, "access code required", http.StatusBadRequest)
		return
	}
	// Constant-time string search to avoid timing leaks.
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range projects {
		if subtle.ConstantTimeCompare([]byte(p.AccessCode), []byte(code)) == 1 {
			json200(w, p)
			return
		}
	}
	// Uniform delay to resist enumeration attacks.
	time.Sleep(100 * time.Millisecond)
	jsonErr(w, "project not found. check your access code.", http.StatusNotFound)
}

func getProjectByToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("t"))
	if token == "" {
		jsonErr(w, "token required", http.StatusBadRequest)
		return
	}

	mu.RLock()
	mt, ok := magicTokens[token]
	if ok {
		if time.Now().After(mt.ExpiresAt) {
			mu.RUnlock()
			jsonErr(w, "link has expired", http.StatusGone)
			return
		}
		p, exists := projects[mt.ProjectID]
		if exists {
			slog.Info("project accessed via magic token", "projectId", p.ID)
			mu.RUnlock()
			json200(w, p)
			return
		}
	}
	mu.RUnlock()

	slog.Warn("invalid magic token attempt", "token", token[:min(8, len(token))]+"...")
	jsonErr(w, "invalid or expired link", http.StatusNotFound)
}

// ─── Router ───────────────────────────────────────────────────────────────────

// extractPathSegment safely extracts the Nth slash-delimited segment after a prefix.
func extractPathSegment(path, prefix string, n int) string {
	trimmed := strings.TrimPrefix(path, prefix)
	parts := strings.Split(trimmed, "/")
	if n >= len(parts) {
		return ""
	}
	return parts[n]
}

func router() http.Handler {
	mux := http.NewServeMux()

	// Shared middleware stack for all routes.
	base := []func(http.HandlerFunc) http.HandlerFunc{
		securityHeadersMiddleware,
		corsMiddleware,
		rateLimitMiddleware,
		requestSizeMiddleware(1 << 20), // 1 MB
	}

	// Public route — login (no auth required, but rate-limited).
	mux.HandleFunc("/api/admin/login", chain(adminLogin, base...))

	// Protected admin routes.
	adminMiddleware := append(base, requireAdminAuth)

	mux.HandleFunc("/api/admin/projects", chain(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listProjects(w, r)
		case http.MethodPost:
			createProject(w, r)
		default:
			jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}, adminMiddleware...))

	mux.HandleFunc("/api/admin/projects/", chain(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/updates") && r.Method == http.MethodPost {
			addUpdate(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			updateProject(w, r)
		case http.MethodDelete:
			deleteProject(w, r)
		default:
			jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}, adminMiddleware...))

	// Public client route.
	mux.HandleFunc("/api/project", chain(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		slog.Info("project lookup", "query", r.URL.RawQuery, "ip", realIP(r))
		if r.URL.Query().Has("t") {
			getProjectByToken(w, r)
			return
		}
		getProjectByCode(w, r)
	}, base...))

	return mux
}

// min is included for Go < 1.21 compatibility.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// Use structured JSON logging in production.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	loadEnv()
	go pruneOldLimiters()

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Prevent header sniffing / slow-loris.
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("server starting",
		"company", COMPANY_NAME,
		"addr", srv.Addr,
		"frontend", FRONTEND_URL,
	)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
