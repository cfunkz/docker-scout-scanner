// Package scanner keeps the inventory of local images in sync with the Docker
// host and schedules, runs and records scans.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/analysis"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/config"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/docker"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/engine"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/intel"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/notify"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

type Job struct {
	ID       int64  `json:"id"`
	ImageID  string `json:"image_id"`
	Name     string `json:"name"`
	Trigger  string `json:"trigger"`
	Force    bool   `json:"force"`
	State    string `json:"state"` // queued|running|done|failed
	Phase    string `json:"phase"`
	Error    string `json:"error,omitempty"`
	Queued   int64  `json:"queued"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
	ScanID   int64  `json:"scan_id"`
}

type Task struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	LastRun int64  `json:"last_run"`
	LastOK  int64  `json:"last_ok"`
	LastErr string `json:"last_error,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Scanner struct {
	st  *store.Store
	cfg *config.Manager
	dk  *docker.Client
	eng *engine.Runner
	log *slog.Logger

	queue chan *Job

	mu        sync.Mutex
	cond      *sync.Cond
	running   int
	pending   map[string]*Job
	recent    []*Job
	nextID    int64
	tasks     map[string]*Task
	dockerOK  bool
	dockerErr string

	dbMu   sync.RWMutex // write-locked while vulnerability DBs update
	syncCh chan struct{}
}

func New(st *store.Store, cfg *config.Manager, dk *docker.Client, eng *engine.Runner, log *slog.Logger) *Scanner {
	s := &Scanner{
		st: st, cfg: cfg, dk: dk, eng: eng, log: log,
		queue:   make(chan *Job, 4096),
		pending: map[string]*Job{},
		tasks:   map[string]*Task{},
		syncCh:  make(chan struct{}, 1),
	}
	s.cond = sync.NewCond(&s.mu)
	for _, n := range []string{"trivy-db", "grype-db", "kev", "epss", "sync"} {
		s.tasks[n] = &Task{Name: n}
	}
	cfg.OnChange(func(config.Settings) {
		s.mu.Lock()
		s.cond.Broadcast() // concurrency may have changed
		s.mu.Unlock()
		s.RequestSync()
	})
	return s
}

// Run starts all background loops; it returns when ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	s.st.RecoverRunning(ctx)
	go s.dispatch(ctx)
	go s.watchEvents(ctx)
	go s.syncLoop(ctx)
	go s.maintenanceLoop(ctx)
	<-ctx.Done()
}

// ---------- queue ----------

func (s *Scanner) Enqueue(imageID, name, trigger string, force bool) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.pending[imageID]; ok {
		if force && j.State == "queued" {
			j.Force = true
		}
		return j, false
	}
	s.nextID++
	j := &Job{ID: s.nextID, ImageID: imageID, Name: name, Trigger: trigger, Force: force, State: "queued", Queued: time.Now().Unix()}
	select {
	case s.queue <- j:
	default:
		return nil, false
	}
	s.pending[imageID] = j
	s.remember(j)
	return j, true
}

func (s *Scanner) remember(j *Job) {
	s.recent = append(s.recent, j)
	if len(s.recent) > 300 {
		s.recent = s.recent[len(s.recent)-300:]
	}
}

func (s *Scanner) Jobs() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0, len(s.recent))
	for i := len(s.recent) - 1; i >= 0; i-- {
		out = append(out, *s.recent[i])
	}
	return out
}

func (s *Scanner) QueueStats() (queued, running int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.pending {
		if j.State == "queued" {
			queued++
		}
	}
	return queued, s.running
}

func (s *Scanner) Tasks() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Task{}
	for _, t := range s.tasks {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Scanner) DockerStatus() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dockerOK, s.dockerErr
}

func (s *Scanner) dispatch(ctx context.Context) {
	for {
		var j *Job
		select {
		case <-ctx.Done():
			return
		case j = <-s.queue:
		}
		s.mu.Lock()
		for s.running >= s.cfg.Get().Concurrency {
			s.cond.Wait()
		}
		s.running++
		j.State, j.Started = "running", time.Now().Unix()
		s.mu.Unlock()
		go func() {
			err := s.scan(ctx, j)
			s.mu.Lock()
			s.running--
			delete(s.pending, j.ImageID)
			j.Finished = time.Now().Unix()
			if err != nil {
				j.State, j.Error = "failed", err.Error()
			} else {
				j.State = "done"
			}
			j.Phase = ""
			s.cond.Broadcast()
			s.mu.Unlock()
			if err != nil {
				s.log.Warn("scan failed", "image", j.Name, "err", err)
			}
		}()
	}
}

func (s *Scanner) phase(j *Job, p string) {
	s.mu.Lock()
	j.Phase = p
	s.mu.Unlock()
}

// ---------- the scan itself ----------

func (s *Scanner) scan(ctx context.Context, j *Job) error {
	cfg := s.cfg.Get()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.ScanTimeoutMin)*time.Minute)
	defer cancel()
	t0 := time.Now()

	im, err := s.st.GetImage(ctx, j.ImageID)
	if err != nil {
		return err
	}
	if im == nil {
		return errors.New("image no longer known")
	}
	ref := ""
	if len(im.RepoTags) > 0 {
		ref = im.RepoTags[0]
	}
	engines := cfg.Engine
	if engines == "both" && !s.eng.HasGrype() {
		engines = "trivy"
	}
	if engines == "grype" && !s.eng.HasGrype() {
		return errors.New("grype selected but not installed")
	}
	scanID, err := s.st.StartScan(ctx, im.ID, ref, engines, j.Trigger)
	if err != nil {
		return err
	}
	s.mu.Lock()
	j.ScanID = scanID
	s.mu.Unlock()
	fail := func(err error) error {
		s.st.FailScan(context.Background(), scanID, err.Error(), time.Since(t0))
		return err
	}

	// 1. SBOM: read the image once, reuse forever (until the image id changes).
	sbomPath := im.SBOMPath
	reused := sbomPath != "" && !j.Force
	if reused {
		if _, err := os.Stat(sbomPath); err != nil {
			reused = false
		}
	}
	if !reused {
		s.phase(j, "reading image")
		sbomPath, err = s.eng.GenerateSBOM(ctx, im.ID, cfg.Offline)
		if err != nil {
			return fail(fmt.Errorf("SBOM generation: %w", err))
		}
		layers := im.Layers
		if ins, err := s.dk.Inspect(ctx, im.ID); err == nil {
			hist, _ := s.dk.History(ctx, im.ID)
			layers = analysis.MapLayers(ins.RootFS.Layers, hist)
		}
		info, err := engine.ReadSBOMInfo(sbomPath)
		if err != nil {
			return fail(fmt.Errorf("read SBOM: %w", err))
		}
		if err := s.st.SetImageSBOM(ctx, im.ID, sbomPath, info.OSFamily, info.OSName, im.EOSL, info.Packages, layers); err != nil {
			return fail(err)
		}
		im.Layers, im.OSFamily, im.OSName, im.PkgCount = layers, info.OSFamily, info.OSName, info.Packages
	}
	info, err := engine.ReadSBOMInfo(sbomPath)
	if err != nil {
		return fail(fmt.Errorf("read SBOM: %w", err))
	}

	// 2. Match against vulnerability DBs.
	if err := s.ensureDB(ctx, engines, cfg.Offline); err != nil {
		return fail(err)
	}
	s.phase(j, "matching")
	s.dbMu.RLock()
	var tr, gr *engine.MatchResult
	var terr, gerr error
	var wg sync.WaitGroup
	if engines == "trivy" || engines == "both" {
		wg.Add(1)
		go func() { defer wg.Done(); tr, terr = s.eng.MatchTrivy(ctx, sbomPath, cfg.Offline) }()
	}
	if engines == "grype" || engines == "both" {
		wg.Add(1)
		go func() { defer wg.Done(); gr, gerr = s.eng.MatchGrype(ctx, sbomPath, cfg.Offline) }()
	}
	wg.Wait()
	s.dbMu.RUnlock()
	if terr != nil {
		return fail(terr)
	}
	if gerr != nil {
		return fail(gerr)
	}
	sets := [][]*store.Finding{}
	eosl := im.EOSL
	if tr != nil {
		sets = append(sets, tr.Findings)
		eosl = tr.EOSL
	}
	if gr != nil {
		sets = append(sets, gr.Findings)
	}
	findings := engine.Merge(sets...)
	engine.FillLayers(findings, info)
	if eosl != im.EOSL {
		_ = s.st.SetImageSBOM(ctx, im.ID, sbomPath, im.OSFamily, im.OSName, eosl, im.PkgCount, im.Layers)
		im.EOSL = eosl
	}

	// 3. Secrets: only when the image was actually re-read; otherwise carry over.
	prev, _ := s.st.PreviousScan(ctx, im.ID, ref, scanID)
	var prevFindings []*store.Finding
	if prev != nil {
		prevFindings, _ = s.st.Findings(ctx, prev.ID)
	}
	if cfg.SecretScanning {
		if !reused || prev == nil || prev.ImageID != im.ID {
			s.phase(j, "secret scan")
			sec, err := s.eng.ScanSecrets(ctx, im.ID, cfg.Offline)
			if err != nil {
				s.log.Warn("secret scan failed", "image", j.Name, "err", err)
			} else {
				findings = append(findings, sec...)
			}
		} else {
			for _, f := range prevFindings {
				if f.Kind == "secret" {
					cp := *f
					findings = append(findings, &cp)
				}
			}
		}
	}

	// 4. Enrich, apply accepted-risk rules, score.
	s.phase(j, "scoring")
	if err := s.enrich(ctx, findings, im, cfg); err != nil {
		s.log.Warn("enrich failed", "err", err)
	}

	sum := &store.ScanSummary{ID: scanID, ImageID: im.ID, SBOMReused: reused}
	for _, f := range findings {
		if f.IgnoredBy != 0 {
			sum.Ignored++
			continue
		}
		if f.Kind == "secret" {
			sum.Secrets++
			continue
		}
		switch f.Severity {
		case "CRITICAL":
			sum.Critical++
		case "HIGH":
			sum.High++
		case "MEDIUM":
			sum.Medium++
		case "LOW":
			sum.Low++
		default:
			sum.Unknown++
		}
		if f.FixedVersion != "" {
			sum.Fixable++
		}
		if f.KEV {
			sum.KEV++
		}
		sum.RiskMax = max(sum.RiskMax, f.Risk)
	}
	sort.Slice(findings, func(a, b int) bool { return findings[a].Risk > findings[b].Risk })

	// 5. Diff against the previous scan of this image or tag.
	var diff analysis.Diff
	if prev != nil && !prev.Pruned {
		sum.PrevScan = prev.ID
		diff = analysis.DiffFindings(prevFindings, findings)
		sum.NewCount, sum.ResolvedCount = len(diff.New), len(diff.Resolved)
	}
	sum.DurationMS = time.Since(t0).Milliseconds()
	if err := s.st.FinishScan(ctx, sum, findings); err != nil {
		return fail(err)
	}
	_, _ = s.st.PruneHistory(ctx, cfg.HistoryKeep)
	_ = s.st.TakeSnapshot(ctx)
	s.log.Info("scan done", "image", j.Name, "ms", sum.DurationMS, "sbom_reused", reused, "crit", sum.Critical, "high", sum.High, "kev", sum.KEV, "new", sum.NewCount)

	// 6. Alert on new, important findings (only when there is a baseline, so
	// the first scan of a fresh install does not flood the channel).
	if prev != nil && cfg.WebhookURL != "" {
		if alert := s.alertFor(cfg, im, diff.New); alert != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := notify.Send(ctx, cfg.WebhookURL, cfg.WebhookFormat, *alert); err != nil {
					s.log.Warn("webhook failed", "err", err)
				}
			}()
		}
	}
	return nil
}

func (s *Scanner) alertFor(cfg config.Settings, im *store.Image, fresh []*store.Finding) *notify.Alert {
	sev := map[string]bool{}
	for _, v := range cfg.NotifySeverities {
		sev[v] = true
	}
	var hit []*store.Finding
	for _, f := range fresh {
		if sev[f.Severity] || (cfg.NotifyKEV && f.KEV) || (cfg.NotifyMinEPSS > 0 && f.EPSS >= cfg.NotifyMinEPSS) || f.Kind == "secret" {
			hit = append(hit, f)
		}
	}
	if len(hit) == 0 {
		return nil
	}
	return &notify.Alert{Image: im.Name(), ImageID: im.ID, InUse: len(im.Containers) > 0, Findings: hit}
}

func (s *Scanner) enrich(ctx context.Context, fs []*store.Finding, im *store.Image, cfg config.Settings) error {
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.VulnID] = true
		for _, a := range strings.Split(f.Aliases, ",") {
			if strings.HasPrefix(a, "CVE-") {
				ids[a] = true
			}
		}
	}
	list := make([]string, 0, len(ids))
	for k := range ids {
		list = append(list, k)
	}
	in, err := s.st.LookupIntel(ctx, list)
	if err != nil {
		return err
	}
	rules, _ := s.st.IgnoreRules(ctx)
	now := time.Now().Unix()
	names := append([]string{}, im.RepoTags...)
	inUse := len(im.Containers) > 0
	for _, f := range fs {
		x, ok := in[f.VulnID]
		if !ok {
			for _, a := range strings.Split(f.Aliases, ",") {
				if y, ok2 := in[a]; ok2 {
					x, ok = y, true
					break
				}
			}
		}
		if ok {
			if cfg.EPSSEnabled {
				f.EPSS, f.EPSSPct = x.EPSS, x.EPSSPct
			}
			if cfg.KEVEnabled {
				f.KEV, f.KEVRansomware = x.KEV, x.Ransom
			}
		}
		f.IgnoredBy = analysis.MatchIgnore(rules, f, names, now)
		f.Risk = analysis.Risk(f, inUse)
	}
	return nil
}

// ensureDB downloads the vulnerability DB for an engine the first time it's needed.
func (s *Scanner) ensureDB(ctx context.Context, engines string, offline bool) error {
	need := []string{}
	if engines != "grype" && !s.eng.TrivyStatus(ctx).Ready {
		need = append(need, "trivy-db")
	}
	if engines != "trivy" && !s.eng.GrypeStatus(ctx).Ready {
		need = append(need, "grype-db")
	}
	if len(need) == 0 {
		return nil
	}
	if offline {
		return fmt.Errorf("offline mode and no vulnerability DB present for %s (mount one into the cache volume)", strings.Join(need, ", "))
	}
	for _, n := range need {
		if err := s.updateDB(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// ---------- inventory sync ----------

func (s *Scanner) RequestSync() {
	select {
	case s.syncCh <- struct{}{}:
	default:
	}
}

// Sync reconciles images and containers with the database and queues scans
// for images that were never scanned.
func (s *Scanner) Sync(ctx context.Context) error {
	t := s.task("sync")
	images, err := s.dk.Images(ctx)
	if err == nil {
		var cs []docker.ContainerSummary
		cs, err = s.dk.Containers(ctx)
		if err == nil {
			err = s.applyInventory(ctx, images, cs)
		}
	}
	s.mu.Lock()
	s.dockerOK, s.dockerErr = err == nil, ""
	if err != nil {
		s.dockerErr = err.Error()
	}
	s.mu.Unlock()
	s.finishTask(t, err, fmt.Sprintf("%d images", len(images)))
	return err
}

func (s *Scanner) applyInventory(ctx context.Context, images []docker.ImageSummary, cs []docker.ContainerSummary) error {
	cfg := s.cfg.Get()
	byImage := map[string][]store.ContainerRef{}
	for _, c := range cs {
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		byImage[c.ImageID] = append(byImage[c.ImageID], store.ContainerRef{Name: name, State: c.State})
	}
	ids := make([]string, 0, len(images))
	for _, di := range images {
		ids = append(ids, di.ID)
		im := &store.Image{ID: di.ID, RepoTags: di.RepoTags, RepoDigests: di.RepoDigests, Created: di.Created, Size: di.Size, Containers: byImage[di.ID]}
		if im.RepoTags == nil {
			im.RepoTags = []string{}
		}
		if im.RepoDigests == nil {
			im.RepoDigests = []string{}
		}
		if im.Containers == nil {
			im.Containers = []store.ContainerRef{}
		}
		im.Excluded = s.excluded(cfg, im)
		if err := s.st.UpsertSeen(ctx, im); err != nil {
			return err
		}
	}
	if err := s.st.MarkAbsent(ctx, ids); err != nil {
		return err
	}
	if cfg.ScanOnStart || cfg.WatchEvents {
		all, err := s.st.ListImages(ctx, false)
		if err != nil {
			return err
		}
		for _, im := range all {
			if im.LatestScan == 0 && s.wanted(cfg, im) {
				s.Enqueue(im.ID, im.Name(), "new", false)
			}
		}
	}
	return nil
}

func (s *Scanner) excluded(cfg config.Settings, im *store.Image) bool {
	for _, p := range cfg.Exclude {
		for _, t := range im.RepoTags {
			if analysis.GlobImage(p, t) {
				return true
			}
		}
		if len(im.RepoTags) == 0 && (p == "<none>" || p == "<untagged>") {
			return true
		}
	}
	return false
}

func (s *Scanner) wanted(cfg config.Settings, im *store.Image) bool {
	if im.Excluded {
		return false
	}
	if cfg.OnlyInUse && len(im.Containers) == 0 {
		return false
	}
	return true
}

// ScanAll queues every wanted image.
func (s *Scanner) ScanAll(ctx context.Context, trigger string, force bool) (int, error) {
	cfg := s.cfg.Get()
	all, err := s.st.ListImages(ctx, false)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, im := range all {
		if s.wanted(cfg, im) {
			if _, ok := s.Enqueue(im.ID, im.Name(), trigger, force); ok {
				n++
			}
		}
	}
	return n, nil
}

func (s *Scanner) syncLoop(ctx context.Context) {
	err := s.Sync(ctx)
	for {
		// Poll every 2 minutes as a safety net for missed events; retry
		// quickly while the Docker API is unreachable (e.g. proxy starting).
		wait := 2 * time.Minute
		if err != nil {
			wait = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-s.syncCh:
			// debounce bursts of events (a compose pull fires dozens)
			time.Sleep(3 * time.Second)
			select {
			case <-s.syncCh:
			default:
			}
		}
		err = s.Sync(ctx)
	}
}

func (s *Scanner) watchEvents(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.dk.Events(ctx, func(ev docker.Event) {
			switch {
			case ev.Type == "image" && (ev.Action == "pull" || ev.Action == "tag" || ev.Action == "untag" || ev.Action == "load" || ev.Action == "import" || ev.Action == "delete" || ev.Action == "create"):
				s.RequestSync()
			case ev.Type == "container" && (ev.Action == "create" || ev.Action == "start" || ev.Action == "die" || ev.Action == "destroy"):
				s.RequestSync()
			}
		})
		if ctx.Err() != nil {
			return
		}
		s.log.Debug("docker event stream ended", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// ---------- maintenance: DB + intel refresh, scheduled rescans ----------

func (s *Scanner) maintenanceLoop(ctx context.Context) {
	time.Sleep(2 * time.Second)
	s.maintain(ctx)
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.maintain(ctx)
		}
	}
}

func (s *Scanner) maintain(ctx context.Context) {
	cfg := s.cfg.Get()
	s.st.PurgeExpiredSessions(ctx)
	if !cfg.Offline {
		day := int64(24 * 3600)
		if cfg.KEVEnabled && s.stale("kev", day) {
			_ = s.RefreshIntel(ctx, "kev")
		}
		if cfg.EPSSEnabled && s.stale("epss", day) {
			_ = s.RefreshIntel(ctx, "epss")
		}
		updated := false
		every := int64(cfg.DBUpdateH) * 3600
		if cfg.Engine != "grype" && s.stale("trivy-db", every) {
			updated = s.updateDB(ctx, "trivy-db") == nil || updated
		}
		if cfg.Engine != "trivy" && s.eng.HasGrype() && s.stale("grype-db", every) {
			updated = s.updateDB(ctx, "grype-db") == nil || updated
		}
		// A fresh DB means fresh CVEs: re-match every image. This is cheap
		// because the SBOMs are cached.
		if updated && s.hasScans(ctx) {
			n, _ := s.ScanAll(ctx, "db-update", false)
			s.log.Info("vulnerability DB updated, re-matching images", "queued", n)
		}
	}
	if cfg.ScanIntervalH > 0 {
		cutoff := time.Now().Add(-time.Duration(cfg.ScanIntervalH) * time.Hour).Unix()
		all, err := s.st.ListImages(ctx, false)
		if err == nil {
			for _, im := range all {
				if s.wanted(cfg, im) && im.Scan != nil && im.Scan.StartedAt < cutoff {
					s.Enqueue(im.ID, im.Name(), "schedule", false)
				}
			}
		}
	}
}

func (s *Scanner) hasScans(ctx context.Context) bool {
	var n int
	_ = s.st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&n)
	return n > 0
}

// stale checks the persisted last-success time of a task.
func (s *Scanner) stale(name string, maxAge int64) bool {
	v, ok := s.st.GetSetting(context.Background(), "task_ok:"+name)
	if !ok {
		return true
	}
	var ts int64
	fmt.Sscan(v, &ts)
	return time.Now().Unix()-ts > maxAge
}

func (s *Scanner) task(name string) *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[name]
	t.Running, t.LastRun = true, time.Now().Unix()
	return t
}

func (s *Scanner) finishTask(t *Task, err error, detail string) {
	s.mu.Lock()
	t.Running = false
	t.Detail = detail
	if err != nil {
		t.LastErr = err.Error()
	} else {
		t.LastErr, t.LastOK = "", time.Now().Unix()
	}
	s.mu.Unlock()
	if err == nil && t.Name != "sync" {
		_ = s.st.SetSetting(context.Background(), "task_ok:"+t.Name, fmt.Sprint(time.Now().Unix()))
	}
}

func (s *Scanner) updateDB(ctx context.Context, name string) error {
	t := s.task(name)
	s.dbMu.Lock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var err error
	if name == "trivy-db" {
		err = s.eng.UpdateTrivyDB(ctx)
	} else {
		err = s.eng.UpdateGrypeDB(ctx)
	}
	s.dbMu.Unlock()
	s.finishTask(t, err, "")
	if err != nil {
		s.log.Warn("DB update failed", "db", name, "err", err)
	}
	return err
}

// UpdateDBs is the admin-triggered refresh of every enabled DB, followed by a re-match.
func (s *Scanner) UpdateDBs(ctx context.Context) error {
	cfg := s.cfg.Get()
	if cfg.Offline {
		return errors.New("offline mode is on")
	}
	var errs []error
	if cfg.Engine != "grype" {
		errs = append(errs, s.updateDB(ctx, "trivy-db"))
	}
	if cfg.Engine != "trivy" && s.eng.HasGrype() {
		errs = append(errs, s.updateDB(ctx, "grype-db"))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	_, err := s.ScanAll(ctx, "db-update", false)
	return err
}

func (s *Scanner) RefreshIntel(ctx context.Context, which string) error {
	cfg := s.cfg.Get()
	if cfg.Offline {
		return errors.New("offline mode is on")
	}
	t := s.task(which)
	var n int
	var err error
	if which == "kev" {
		n, err = intel.UpdateKEV(ctx, s.st, cfg.KEVURL)
	} else {
		n, err = intel.UpdateEPSS(ctx, s.st, cfg.EPSSURL)
	}
	s.finishTask(t, err, fmt.Sprintf("%d entries", n))
	if err != nil {
		s.log.Warn("intel refresh failed", "feed", which, "err", err)
	}
	return err
}
