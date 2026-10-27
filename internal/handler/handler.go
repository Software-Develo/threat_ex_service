package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Software-Develo/threat_ex_service/api"
	"github.com/Software-Develo/threat_ex_service/internal/storage"
)

// регулярки
var (
	md5Regexp    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Regexp = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	cveRegexp    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

type ThreatStore interface {
	Get(ctx context.Context, md5 string) (*storage.Threat, error)
	Create(ctx context.Context, t storage.Threat) (*storage.Threat, error)
	Update(ctx context.Context, t storage.Threat) (*storage.Threat, error)
}

type Handler struct {
	store ThreatStore
}

func New(store ThreatStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req api.ThreatCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", "Body must be valid JSON")
		return
	}

	if !md5Regexp.MatchString(req.Md5) {
		respondError(w, http.StatusBadRequest, "Validation failed", "md5 must be 32 hexadecimal characters")
		return
	}

	t := buildThreat(req.Md5, req.Name, req.Type, req.Severity, req.Description, req.Sha256, req.Cve, req.Playbook, req.VulnStatus)

	if err := validate(t); err != nil {
		respondError(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	created, err := h.store.Create(r.Context(), t)
	if errors.Is(err, storage.ErrAlreadyExists) {
		respondError(w, http.StatusConflict, "Threat already exists", "A threat with MD5 "+t.MD5+" already exists")
		return
	}
	if err != nil {
		log.Printf("create threat: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	respondJSON(w, http.StatusCreated, toResponse(created))
}

func (h *Handler) GetInfoByMd5(w http.ResponseWriter, r *http.Request, md5 string) {
	if !md5Regexp.MatchString(md5) {
		respondError(w, http.StatusBadRequest, "Invalid MD5", "MD5 must be 32 hexadecimal characters")
		return
	}

	t, err := h.store.Get(r.Context(), strings.ToLower(md5))
	if errors.Is(err, storage.ErrNotFound) {
		respondError(w, http.StatusNotFound, "Threat not found", "No threat with MD5 "+md5+" found")
		return
	}
	if err != nil {
		log.Printf("get threat: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	respondJSON(w, http.StatusOK, toResponse(t))
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request, md5 string) {
	if !md5Regexp.MatchString(md5) {
		respondError(w, http.StatusBadRequest, "Invalid MD5", "MD5 must be 32 hexadecimal characters")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req api.ThreatUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", "Body must be valid JSON")
		return
	}

	t := buildThreat(md5, req.Name, req.Type, req.Severity, req.Description, req.Sha256, req.Cve, req.Playbook, req.VulnStatus)

	if err := validate(t); err != nil {
		respondError(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	updated, err := h.store.Update(r.Context(), t)
	if errors.Is(err, storage.ErrNotFound) {
		respondError(w, http.StatusNotFound, "Threat not found", "No threat with MD5 "+t.MD5+" found")
		return
	}
	if err != nil {
		log.Printf("update threat: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	respondJSON(w, http.StatusOK, toResponse(updated))
}

func buildThreat(
	md5, name string,
	typ api.ThreatType,
	severity api.Severity,
	desc, sha *string,
	cve *api.CveList,
	playbook *api.Playbook,
	vs *api.VulnStatus,
) storage.Threat {
	t := storage.Threat{
		MD5:        strings.ToLower(md5),
		Name:       name,
		Type:       string(typ),
		Severity:   string(severity),
		VulnStatus: string(api.Unknown),
	}
	if desc != nil {
		t.Description = *desc
	}
	if sha != nil {
		s := strings.ToLower(*sha)
		t.SHA256 = &s
	}
	if cve != nil {
		t.CVE = *cve
	}
	if playbook != nil {
		t.Playbook = *playbook
	}
	if vs != nil {
		t.VulnStatus = string(*vs)
	}
	return t
}

func validate(t storage.Threat) error {
	if strings.TrimSpace(t.Name) == "" || utf8.RuneCountInString(t.Name) > 255 {
		return errors.New("name must be 1-255 characters")
	}
	if !api.ThreatType(t.Type).Valid() {
		return errors.New("type must be one of: trojan, ransomware, worm, spyware, adware, other")
	}
	if !api.Severity(t.Severity).Valid() {
		return errors.New("severity must be one of: low, medium, high, critical")
	}
	if !api.VulnStatus(t.VulnStatus).Valid() {
		return errors.New("vuln_status must be one of: unpatched, patch_available, patched, unknown")
	}
	if utf8.RuneCountInString(t.Description) > 1000 {
		return errors.New("description must be at most 1000 characters")
	}
	if t.SHA256 != nil && !sha256Regexp.MatchString(*t.SHA256) {
		return errors.New("sha256 must be 64 hexadecimal characters")
	}
	if len(t.CVE) > 20 {
		return errors.New("cve must contain at most 20 items")
	}
	for _, c := range t.CVE {
		if !cveRegexp.MatchString(c) {
			return errors.New("cve items must look like CVE-2017-0144")
		}
	}
	if len(t.Playbook) > 20 {
		return errors.New("playbook must contain at most 20 steps")
	}
	for _, step := range t.Playbook {
		if utf8.RuneCountInString(step) > 500 {
			return errors.New("each playbook step must be at most 500 characters")
		}
	}
	return nil
}

func toResponse(t *storage.Threat) api.ThreatResponse {
	resp := api.ThreatResponse{
		Md5:        t.MD5,
		Name:       t.Name,
		Type:       api.ThreatType(t.Type),
		Severity:   api.Severity(t.Severity),
		Sha256:     t.SHA256,
		Cve:        t.CVE,
		Playbook:   t.Playbook,
		VulnStatus: api.VulnStatus(t.VulnStatus),
		CreatedAt:  t.CreatedAt,
		UpdatedAt:  t.UpdatedAt,
	}
	if t.Description != "" {
		resp.Description = &t.Description
	}
	return resp
}

func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, message, details string) {
	resp := api.ErrorResponse{Message: &message}
	if details != "" {
		resp.Details = &details
	}
	respondJSON(w, status, resp)
}
