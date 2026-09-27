package siemuc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// TickBudget bounds one worker pass. A slow sink cannot consume the whole pass.
type TickBudget struct {
	MaxPartitions int
	Deadline      time.Time
}

// TickStats counts what one pass did. It is safe to log; it has no payloads.
type TickStats struct {
	Partitions int
	Sent       int
	Blocked    int
	Idle       int
}

// Backfill copies a bounded page of historical incident identities into the
// historical partition. It does not claim those rows happened before live
// capture.
func (s *Service) Backfill(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	return s.sources.BackfillIncidents(ctx, limit)
}

// Tick visits a fair slice of tenants and advances partitions whose lease
// this worker can hold. Network IO happens outside the store's commit.
func (s *Service) Tick(ctx context.Context, workerID string, budget TickBudget) (TickStats, error) {
	if workerID == "" {
		return TickStats{}, invalid("siem worker id is required")
	}
	if budget.MaxPartitions <= 0 || budget.MaxPartitions > siem.MaxTickPartitions {
		budget.MaxPartitions = siem.MaxTickPartitions
	}
	tenants, err := s.directory.TenantIDs(ctx)
	if err != nil {
		return TickStats{}, err
	}
	if len(tenants) == 0 {
		return TickStats{}, nil
	}
	start := int(s.turn.Add(1)-1) % len(tenants)
	var stats TickStats
	for n := 0; n < len(tenants) && stats.Partitions < budget.MaxPartitions; n++ {
		if !budget.Deadline.IsZero() && !s.clock.Now().Before(budget.Deadline) {
			break
		}
		tenant := tenants[(start+n)%len(tenants)]
		tenantCtx := shared.WithTenant(ctx, tenant)
		sinks, err := s.store.ListSinks(tenantCtx)
		if err != nil {
			return stats, err
		}
		for _, sink := range sinks {
			if stats.Partitions >= budget.MaxPartitions {
				break
			}
			if !budget.Deadline.IsZero() && !s.clock.Now().Before(budget.Deadline) {
				break
			}
			for _, source := range partitions() {
				if stats.Partitions >= budget.MaxPartitions {
					break
				}
				outcome, err := s.advance(tenantCtx, workerID, sink, source)
				if err != nil {
					return stats, err
				}
				stats.Partitions++
				switch outcome {
				case outcomeSent:
					stats.Sent++
				case outcomeBlocked:
					stats.Blocked++
				default:
					stats.Idle++
				}
			}
		}
	}
	_ = s.store.Prune(shared.WithTenant(ctx, tenants[start]), s.clock.Now().Add(-siem.ManifestRetention))
	return stats, nil
}

type outcome int

const (
	outcomeIdle outcome = iota
	outcomeSent
	outcomeBlocked
)

func (s *Service) advance(ctx context.Context, workerID string, sink siem.Sink, source siem.Source) (outcome, error) {
	if !sink.Enabled || sink.Paused || sink.BlockedReason != "" {
		return outcomeIdle, nil
	}
	now := s.clock.Now().UTC()
	lease, err := s.store.Claim(ctx, workerID, sink, source, now, siem.DefaultLease)
	if err != nil {
		if errors.Is(err, siem.ErrStaleLease) {
			return outcomeIdle, nil
		}
		return outcomeIdle, err
	}
	release := true
	defer func() {
		if release {
			_ = s.store.Release(ctx, lease)
		}
	}()
	batch, sealed, ok, err := s.store.OpenBatch(ctx, sink.ID, source)
	if err != nil {
		return outcomeIdle, err
	}
	if ok && (batch.Generation != sink.Generation || s.policyStale(ctx, sink, batch)) {
		batch.State = siem.BatchInvalid
		batch.UpdatedAt = now
		if err := s.store.SaveBatch(ctx, batch, nil); err != nil {
			return outcomeIdle, err
		}
		ok = false
	}
	if ok && !batch.NextAttemptAt.IsZero() && now.Before(batch.NextAttemptAt) {
		return outcomeIdle, nil
	}
	if !ok {
		prepared, payloads, problem, err := s.prepare(ctx, sink, source, lease, now)
		if err != nil {
			return outcomeIdle, err
		}
		if !problem.None() {
			return s.block(ctx, sink, source, problem), nil
		}
		if prepared.ID.IsZero() {
			return outcomeIdle, nil
		}
		batch = prepared
		sealed = payloads
	}
	if siem.HandledPrefix(batch.Items) == len(batch.Items) {
		if err := s.finish(ctx, lease, batch, now); err != nil {
			return outcomeIdle, err
		}
		return outcomeSent, nil
	}
	secret, err := s.openSecret(ctx, sink)
	if err != nil {
		return s.block(ctx, sink, source, siem.Problem{Kind: "blocked", Message: "credential unavailable"}), nil
	}
	driver := s.drivers[sink.Provider]
	if driver == nil {
		return s.block(ctx, sink, source, siem.Problem{Kind: "blocked", Message: "provider is not wired"}), nil
	}
	pending, err := s.outbound(ctx, sink, batch, sealed)
	if err != nil {
		return s.block(ctx, sink, source, siem.Problem{Kind: "blocked", Message: "prepared payload could not be opened"}), nil
	}
	if len(pending) == 0 {
		if err := s.finish(ctx, lease, batch, now); err != nil {
			return outcomeIdle, err
		}
		return outcomeSent, nil
	}
	batch.State = siem.BatchSending
	batch.UpdatedAt = now
	if err := s.store.SaveBatch(ctx, batch, sealed); err != nil {
		return outcomeIdle, err
	}
	result, err := driver.Deliver(ctx, siem.Delivery{
		Origin: sink.Origin, Secret: secret, Target: sink.Target, Channel: sink.Channel,
		AckMode: sink.AckMode, Records: pending,
	})
	if err != nil {
		batch.Attempt++
		batch.NextAttemptAt = siem.RetryAt(now, batch.Attempt, 0, s.rng)
		batch.State = siem.BatchPartial
		batch.Diagnostic = siem.SafeDiagnostic(err.Error())
		batch.UpdatedAt = s.clock.Now().UTC()
		if err := s.store.SaveBatch(ctx, batch, sealed); err != nil {
			return outcomeIdle, err
		}
		s.metrics.Retry(string(sink.Provider))
		return outcomeIdle, nil
	}
	if len(result.Items) != len(pending) {
		return s.block(ctx, sink, source, siem.Problem{Kind: "blocked", Message: "provider response did not match the batch"}), nil
	}
	blocked := false
	var retryAfter time.Duration
	cursor := 0
	for i := range batch.Items {
		if batch.Items[i].Disposition != siem.ItemPending {
			continue
		}
		item := result.Items[cursor]
		cursor++
		batch.Items[i].SafeReason = siem.SafeDiagnostic(item.Diagnostic)
		switch {
		case item.Blocked || !item.Retryable && item.Disposition != siem.ItemAcked:
			batch.Items[i].Disposition = siem.ItemFailed
			blocked = true
		case item.Disposition == siem.ItemAcked:
			batch.Items[i].Disposition = siem.ItemAcked
		default:
			if item.RetryAfter > retryAfter {
				retryAfter = item.RetryAfter
			}
		}
	}
	batch.State = siem.NextState(batch.Items, blocked)
	batch.UpdatedAt = s.clock.Now().UTC()
	if blocked {
		batch.Diagnostic = firstFailure(batch)
		sink.BlockedReason = batch.Diagnostic
		sink.Version++
		sink.UpdatedAt = batch.UpdatedAt
		if err := s.store.UpdateSink(ctx, sink, sink.Version-1); err != nil {
			return outcomeIdle, err
		}
		s.metrics.Blocked(batch.Diagnostic)
	} else if batch.State != siem.BatchAcked {
		batch.Attempt++
		batch.NextAttemptAt = siem.RetryAt(now, batch.Attempt, retryAfter, s.rng)
		s.metrics.Retry(string(sink.Provider))
	}
	if err := s.finish(ctx, lease, batch, s.clock.Now().UTC()); err != nil {
		return outcomeIdle, err
	}
	s.metrics.Batch(string(sink.Provider), string(batch.State))
	s.metrics.Items(string(sink.Provider), string(siem.ItemAcked), siem.HandledPrefix(batch.Items))
	if batch.State == siem.BatchBlocked {
		return outcomeBlocked, nil
	}
	return outcomeSent, nil
}

func (s *Service) prepare(ctx context.Context, sink siem.Sink, source siem.Source, lease siem.Lease, now time.Time) (siem.Batch, []string, siem.Problem, error) {
	cp, _, err := s.store.Checkpoint(ctx, sink.ID, source)
	if err != nil {
		return siem.Batch{}, nil, siem.Problem{}, err
	}
	if cp.Source == "" {
		cp.Source = source
		cp.Position.Source = source
	}
	var exports []built
	var problem siem.Problem
	switch source {
	case siem.SourceAudit:
		exports, problem, err = s.prepareAudit(ctx, sink, cp)
	case siem.SourceIncidentLive:
		exports, problem, err = s.prepareIncident(ctx, sink, cp, siem.PhaseLive)
	default:
		exports, problem, err = s.prepareIncident(ctx, sink, cp, siem.PhaseHistorical)
	}
	if err != nil || !problem.None() || len(exports) == 0 {
		return siem.Batch{}, nil, problem, err
	}
	batch := siem.Batch{
		ID: s.ids.NewID(), TenantID: sink.TenantID, SinkID: sink.ID, Source: source,
		Generation: sink.Generation, LeaseToken: lease.Token, State: siem.BatchPrepared,
		PolicyVersion: string(sink.DataClass) + "/" + siem.ScrubberVersion, MappingVersion: siem.MappingVersion,
		CreatedAt: now, UpdatedAt: now,
	}
	sealed := make([]string, len(exports))
	for i, built := range exports {
		batch.Items = append(batch.Items, built.item)
		if built.export.Disposition != siem.ItemPending {
			continue
		}
		sealed[i], err = s.sealer.Seal(ctx, built.export.Body, payloadAAD(sink, built.item.RecordID))
		if err != nil {
			return siem.Batch{}, nil, siem.Problem{}, err
		}
		if len(sealed[i]) > siem.MaxSealedBytes {
			batch.Items[i].Disposition = siem.ItemQuarantined
			batch.Items[i].SafeReason = "sealed payload exceeds the cap"
			sealed[i] = ""
		}
	}
	if len(batch.Items) > 0 {
		batch.ChainHead = exports[len(exports)-1].chain
	}
	if err := s.store.SaveBatch(ctx, batch, sealed); err != nil {
		return siem.Batch{}, nil, siem.Problem{}, err
	}
	return batch, sealed, siem.Problem{}, nil
}

type built struct {
	item   siem.BatchItem
	export siem.Exported
	chain  string
}

func (s *Service) prepareAudit(ctx context.Context, sink siem.Sink, cp siem.Checkpoint) ([]built, siem.Problem, error) {
	rows, meta, anchor, err := s.sources.ReadAudit(ctx, cp.Position.AuditID, siem.MaxBatchRecords)
	if err != nil {
		return nil, siem.Problem{}, err
	}
	accepted, problem := siem.VerifyAuditContent(cp.Position, rows, meta, anchor)
	if !problem.None() && len(accepted) == 0 {
		s.metrics.Gap(string(siem.SourceAudit))
		return nil, problem, nil
	}
	secret, err := s.openSecret(ctx, sink)
	if err != nil {
		return nil, siem.Problem{Kind: "blocked", Message: "credential unavailable"}, nil
	}
	var out []built
	var bytes int
	for _, row := range accepted {
		class, _, err := siem.EffectiveClass(sink.DataClass, row.EngagementID, s.ceiling(ctx, row.EngagementID))
		if err != nil {
			return nil, siem.Problem{Kind: "blocked", Message: "data class is invalid"}, nil
		}
		exported := siem.ExportAudit(sink.TenantID.String(), row, class, []string{secret}, s.publicBase)
		item := siem.BatchItem{
			Ordinal: len(out), RecordID: exported.RecordID, DataClass: class, EngagementID: row.EngagementID,
			Disposition: exported.Disposition, PayloadDigest: exported.Digest, Mapping: exported.Format,
			SafeReason: exported.Reason,
			Position:   siem.Position{Source: siem.SourceAudit, AuditID: row.ID, AuditHash: row.Hash, HashVersion: 2},
		}
		if exported.Digest == "" {
			item.PayloadDigest = "none"
		}
		bytes += len(exported.Body)
		if bytes > siem.MaxBatchBytes && len(out) > 0 {
			break
		}
		out = append(out, built{item: item, export: exported, chain: row.Hash})
	}
	if !problem.None() {
		s.metrics.Gap(string(siem.SourceAudit))
	}
	return out, siem.Problem{}, nil
}

func (s *Service) prepareIncident(ctx context.Context, sink siem.Sink, cp siem.Checkpoint, phase siem.Phase) ([]built, siem.Problem, error) {
	rows, err := s.sources.ReadIncident(ctx, phase, cp.Position.StreamSeq, siem.MaxBatchRecords)
	if err != nil {
		return nil, siem.Problem{}, err
	}
	accepted, problem := siem.VerifyIncidentPage(cp.Position, rows)
	if !problem.None() && len(accepted) == 0 {
		s.metrics.Gap(string(phase))
		return nil, problem, nil
	}
	secret, err := s.openSecret(ctx, sink)
	if err != nil {
		return nil, siem.Problem{Kind: "blocked", Message: "credential unavailable"}, nil
	}
	source := siem.SourceIncidentLive
	if phase == siem.PhaseHistorical {
		source = siem.SourceIncidentHistorical
	}
	var out []built
	var bytes int
	for _, row := range accepted {
		class, _, err := siem.EffectiveClass(sink.DataClass, row.EngagementID, s.ceiling(ctx, row.EngagementID))
		if err != nil {
			return nil, siem.Problem{Kind: "blocked", Message: "data class is invalid"}, nil
		}
		exported := siem.ExportIncident(sink.TenantID.String(), row, class, []string{secret}, s.publicBase)
		item := siem.BatchItem{
			Ordinal: len(out), RecordID: exported.RecordID, DataClass: class, EngagementID: row.EngagementID,
			Disposition: exported.Disposition, PayloadDigest: exported.Digest, Mapping: exported.Format,
			SafeReason: exported.Reason,
			Position:   siem.Position{Source: source, StreamSeq: row.StreamSeq, IncidentID: row.IncidentID, EventSeq: row.EventSeq, Phase: phase},
		}
		if exported.Digest == "" {
			item.PayloadDigest = "none"
		}
		bytes += len(exported.Body)
		if bytes > siem.MaxBatchBytes && len(out) > 0 {
			break
		}
		out = append(out, built{item: item, export: exported})
	}
	return out, siem.Problem{}, nil
}

func (s *Service) policyStale(ctx context.Context, sink siem.Sink, batch siem.Batch) bool {
	if batch.PolicyVersion != string(sink.DataClass)+"/"+siem.ScrubberVersion {
		return true
	}
	for _, item := range batch.Items {
		class, _, err := siem.EffectiveClass(sink.DataClass, item.EngagementID, s.ceiling(ctx, item.EngagementID))
		if err != nil {
			return true
		}
		got, gok := class.Rank()
		have, hok := item.DataClass.Rank()
		if !gok || !hok || got < have {
			return true
		}
	}
	return false
}

func (s *Service) block(ctx context.Context, sink siem.Sink, source siem.Source, problem siem.Problem) outcome {
	sink.BlockedReason = siem.SafeDiagnostic(problem.Message)
	if sink.BlockedReason == "" {
		sink.BlockedReason = problem.Kind
	}
	sink.Version++
	sink.UpdatedAt = s.clock.Now().UTC()
	if err := s.store.UpdateSink(ctx, sink, sink.Version-1); err != nil {
		return outcomeBlocked
	}
	s.metrics.Blocked(sink.BlockedReason)
	s.metrics.Gap(string(source))
	return outcomeBlocked
}

func (s *Service) finish(ctx context.Context, lease siem.Lease, batch siem.Batch, now time.Time) error {
	cp := siem.Checkpoint{
		SinkID: batch.SinkID, TenantID: batch.TenantID, Source: batch.Source,
		Generation: batch.Generation, ChainHead: batch.ChainHead, UpdatedAt: now,
	}
	if pos, ok := siem.AdvancePosition(batch.Items); ok {
		cp.Position = pos
	} else if current, found, err := s.store.Checkpoint(ctx, batch.SinkID, batch.Source); err != nil {
		return err
	} else if found {
		cp.Position = current.Position
		if cp.ChainHead == "" {
			cp.ChainHead = current.ChainHead
		}
	}
	return s.store.Commit(ctx, lease, batch, cp, now)
}

func (s *Service) outbound(ctx context.Context, sink siem.Sink, batch siem.Batch, sealed []string) ([]siem.DeliveryRecord, error) {
	var records []siem.DeliveryRecord
	for i, item := range batch.Items {
		if item.Disposition != siem.ItemPending || i >= len(sealed) || sealed[i] == "" {
			continue
		}
		plain, err := s.sealer.Open(ctx, sealed[i], payloadAAD(sink, item.RecordID))
		if err != nil {
			return nil, err
		}
		records = append(records, siem.DeliveryRecord{ID: item.RecordID, Body: plain})
	}
	return records, nil
}

func payloadAAD(sink siem.Sink, recordID string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d|%s", sink.TenantID, sink.ID, sink.Provider, sink.Generation, recordID))
}

func firstFailure(batch siem.Batch) string {
	for _, item := range batch.Items {
		if item.Disposition == siem.ItemFailed && item.SafeReason != "" {
			return item.SafeReason
		}
	}
	return "provider rejected a record"
}
