package notification

import (
	"context"
	"fmt"
	"strconv"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// eventBuilders declares the builder of every catalog event type. Variables whose value the
// source row does not hold yet (engagement, project, finding, team and asset names, the scan
// target, the failed condition count) are declared in the catalog and filled when the capture
// moves to identity only (#1344 part 2); until then a template reads them as empty.
func eventBuilders() map[domain.EventType]eventBuilder {
	return map[domain.EventType]eventBuilder{
		domain.EventVulnerabilityAction: {
			vars: func(e domain.Event, data eventData) map[string]string {
				return map[string]string{"severity": string(e.Severity), "action_type": data.text("action_type")}
			},
		},
		domain.EventScanCompleted: {
			subjectKey: "scan_id",
			vars: func(_ domain.Event, data eventData) map[string]string {
				return map[string]string{"scan_kind": data.text("scan_kind")}
			},
			relevant: scanStillSucceeded,
		},
		domain.EventQualityGateFailed: {subjectKey: "analysis_id"},
		domain.EventSLAApproaching: {
			subjectKey: "finding_id",
			vars: func(_ domain.Event, data eventData) map[string]string {
				deadline, _ := data.time("deadline")
				return map[string]string{"deadline": formatTime(deadline), "lead_time_hours": leadTimeHours(data)}
			},
			relevant: slaReminderStillDue,
		},
		domain.EventFleetAgentOffline: {
			subjectKey: "agent_id",
			vars: func(_ domain.Event, data eventData) map[string]string {
				lastSeen, _ := data.time("last_seen_at")
				return map[string]string{"last_seen_at": formatTime(lastSeen)}
			},
			relevant: fleetAgentStillOffline,
		},
		domain.EventIncidentCreated: {
			subjectKey: "incident_id",
			vars: func(e domain.Event, _ eventData) map[string]string {
				return map[string]string{"severity": string(e.Severity)}
			},
		},
		domain.EventOwnershipChanged: {
			subjectKey: "finding_id",
			vars: func(_ domain.Event, data eventData) map[string]string {
				return map[string]string{"actor": data.text("actor"), "reason": data.text("reason")}
			},
		},
		domain.EventChannelPaused:      {subjectKey: "channel_id"},
		domain.EventDestinationChanged: {},
		domain.EventTest:               {},
	}
}

// scanStillSucceeded holds back a scan.completed delivery whose job no longer reads as succeeded,
// for example a CI import rejected after capture. Only events captured from scan_jobs are checked.
func scanStillSucceeded(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, _ eventData) (bool, error) {
	if work.Event.SourceKind != "scan_job" {
		return true, nil
	}
	return facts.ScanJobSucceeded(ctx, work.Event.TenantID, work.Event.SourceID)
}

// slaReminderStillDue holds back a reminder whose assessment was replaced, rescheduled, excepted
// or closed, or whose deadline already passed.
func slaReminderStillDue(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	deadline, ok := data.time("deadline")
	if !ok {
		return false, fmt.Errorf("%w: decode SLA notification event", shared.ErrValidation)
	}
	return facts.SLAReminderDue(ctx, work.Event.TenantID, ports.SLAReminder{
		AssessmentID: data.text("assessment_id"), EngagementID: data.text("engagement_id"),
		FindingID: data.text("finding_id"), Deadline: deadline,
	})
}

// fleetAgentStillOffline holds back an offline notice once the agent has checked in again or left
// the fleet.
func fleetAgentStillOffline(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	lastSeen, ok := data.time("last_seen_at")
	if !ok {
		return false, fmt.Errorf("%w: decode fleet notification event", shared.ErrValidation)
	}
	return facts.FleetAgentLastSeen(ctx, work.Event.TenantID, data.text("agent_id"), lastSeen)
}

func leadTimeHours(data eventData) string {
	seconds, err := strconv.ParseFloat(data.text("lead_time_seconds"), 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return strconv.FormatFloat(seconds/3600, 'f', -1, 64)
}
