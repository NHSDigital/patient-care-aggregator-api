# Task Resource Alignment Summary

## Overview
The Consumer spec Task resource has been updated to align with the Producer spec's generic FHIR-based Task implementation. This enables the Task resource to support multiple use cases (questionnaires, appointment booking invites, and future task types) while maintaining backwards compatibility with the existing Questionnaire resource.

## Why This Change?

### Previous Implementation
- **Questionnaire-centric**: The Consumer Task resource was essentially a copy of the Questionnaire resource with additional fields for appointment booking invites
- **Limited extensibility**: The `kind` enum was rigid and required updates for each new task type
- **Misaligned with Producer spec**: The Consumer spec Task didn't follow the producer-side FHIR Task pattern
- **Redundancy**: Similar fields and logic across Questionnaire and Task resources

### New Implementation
- **Generic task framework**: Task resource can represent any patient action (questionnaires, booking invites, etc.)
- **FHIR R4 aligned**: Follows standard FHIR Task structure with fields like `status`, `intent`, `reasonCode`, `reasonReference`
- **Producer-spec aligned**: Matches the Producer API standards for consistency across the aggregator ecosystem
- **Future-proof**: Extensible via `reasonCode` and extensions for new task types
- **Cleaner architecture**: Single generic Task resource instead of type-specific variants

## Key Changes

### Removed Fields
- **`kind`** → Replaced by `reasonCode` (provides more semantic meaning)
- **`scheduledPeriod`** → Replaced by `restriction.period` (FHIR standard)
- **`performer`** → Replaced by `owner` (FHIR standard terminology)

### Added Fields
| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| `id` | string | Yes | Globally unique identifier for the task |
| `identifier` | object | No | System-specific identifier (portal database ID) |
| `intent` | string | Yes | Always "plan" - indicates task intent |
| `authored` | date-time | Yes | When task became available to patient |
| `lastModified` | date-time | No | When task was last modified by patient |
| `restriction.period` | object | No | Start/end dates for task deadline |
| `focus` | object | No | Reference to linked Appointment (if applicable) |
| `for` | object | Yes | Patient identifier (NHS number) |
| `owner` | object | Yes | Responsible organization (provider) |
| `basedOn` | array | No | Optional reference to care pathway |
| `reasonCode` | object | Yes | Codes and text for task type classification |
| `reasonReference` | object | Yes | Reference to Questionnaire or AppointmentBooking |

### Modified Fields
- **`status`**: Changed from `["not-started", "in-progress", "completed", "cancelled"]` to FHIR-compliant `["requested", "rejected", "cancelled", "in-progress", "completed"]`
- **`statusReason`**: Now structured as codeable concept (ready for future expansion)
- **`description`**: Enhanced with clearer guidance for both questionnaires and invites
- **`extension`**: Streamlined to include Portal Link, Client ID, and Treatment Function (for PIFU only)

## Task Type Classification

### Using `reasonCode` to Distinguish Task Types

The new `reasonCode` structure replaces the old `kind` enum and provides semantic clarity:

#### For Questionnaires:
```yaml
reasonCode:
  coding:
    - system: "https://fhir.nhs.uk/StructureDefinition/Extension-Questionnaire-Type"
      code: "pifu-triage"  # or other questionnaire codes
      display: "PIFU Triage Questionnaire"
  text: "Patient Initiated Follow-Up Questionnaire"
```

#### For Appointment Booking Invites:
```yaml
reasonCode:
  coding:
    - system: "https://fhir.nhs.uk/StructureDefinition/Extension-Task-Type"
      code: "appointment-booking-invite"
      display: "Appointment Booking Invitation"
  text: "Invitation to book an appointment"
```

## Backwards Compatibility

### Questionnaire Resource Preserved
- The existing `Questionnaire` resource remains **unchanged**
- Current consumers can continue using the Questionnaire resource without modification
- No breaking changes to the Questionnaire schema

### Migration Path
1. **Phase 1 (Current)**: Both Task and Questionnaire resources available
2. **Phase 2 (Future)**: Clients should migrate to using Task for new questionnaire implementations
3. **Phase 3 (Future)**: Questionnaire resource may be deprecated (with advance notice)

## Data Models

### Appointment Booking Invite (Task)
```yaml
id: ad8baee0-f2b2-4258-ad25-a8de19c32c14
status: requested
intent: plan
description: Book your Dermatology appointment
authored: '2025-07-16T09:00:00.000Z'
reasonCode:
  coding:
    - system: "https://fhir.nhs.uk/StructureDefinition/Extension-Task-Type"
      code: "appointment-booking-invite"
  text: "Invitation to book an appointment"
reasonReference:
  type: AppointmentBooking
  reference: "https://my.portal.com/AppointmentBooking/ad8baee0-f2b2-4258-ad25-a8de19c32c14"
for:
  type: Patient
  identifier:
    system: "https://fhir.nhs.uk/Id/nhs-number"
    value: "9000000002"
owner:
  type: Organization
  identifier:
    system: "https://fhir.nhs.uk/Id/ods-organization-code"
    value: "RXP"
  display: "COUNTY DURHAM AND DARLINGTON NHS FOUNDATION TRUST"
```

### Questionnaire (Task)
```yaml
id: c21417eb-ffef-4a9e-b367-ebd8b8c29e7c
status: requested
intent: plan
description: Dermatology PIFU follow-up questionnaire
authored: '2025-06-20T18:00:00.000Z'
reasonCode:
  coding:
    - system: "https://fhir.nhs.uk/StructureDefinition/Extension-Questionnaire-Type"
      code: "pifu-triage"
  text: "Patient Initiated Follow-Up Questionnaire"
reasonReference:
  type: Questionnaire
  reference: "https://my.portal.com/Questionnaire/c21417eb-ffef-4a9e-b367-ebd8b8c29e7c"
extension:
  - url: "https://fhir.nhs.uk/StructureDefinition/Extension-Task-TreatmentFunction"
    valueCoding:
      system: "https://fhir.nhs.uk/CodeSystem/Specialty-1"
      code: "330"
      display: "Dermatology"
```

## Examples Updated

### Appointment Booking Invites (6 examples)
1. ✅ Basic invitation (not started)
2. ✅ With expiry date (requested, not started)
3. ✅ Started but incomplete (in-progress)
4. ✅ Completed (with linked appointment)
5. ✅ Cancelled (no response within booking window)
6. ✅ Rejected (patient condition resolved)

### Questionnaires (2 new examples)
1. ✅ PIFU questionnaire (with treatment function extension)
2. ✅ Pre-assessment questionnaire (linked to appointment)

## Implementation Notes

### For Consumer API Users
- **No immediate changes required** if using Questionnaire resource
- **Optional migration**: Adopt Task resource for future questionnaire implementations
- **New integrations**: Use Task resource for all task types

### For Portal Providers (Producer API)
- **Already implemented**: Producer spec Task resource remains unchanged
- **Consistency**: Consumer spec now aligns with Producer spec
- **Contract testing**: Ensure portal systems work with both old Questionnaire and new Task patterns during transition

### For the Aggregator Service
- **Data mapping**: When aggregating from portals, map incoming Task data to both Questionnaire (for backwards compatibility) and Task resources
- **Gradual rollout**: Transition consumers to Task resource over time
- **Validation**: Ensure both resourceType patterns are properly validated

## Status Values Mapping

| Old (Questionnaire) | New (Task) | Meaning |
|-------------------|-----------|---------|
| `not-started` | `requested` | Task available but not yet started |
| `in-progress` | `in-progress` | Task started by patient |
| `completed` | `completed` | Task finished by patient |
| `cancelled` | `cancelled` | Task cancelled by system or patient |
| (new) | `rejected` | Patient explicitly declined task |

## Extension Framework

The streamlined extensions provide:

1. **Portal Link** (required)
   - Deep link to patient-facing portal interface
   - System: `https://fhir.nhs.uk/StructureDefinition/Extension-Portal-Link`

2. **Client ID** (optional)
   - Upstream system identifier
   - System: `https://fhir.nhs.uk/StructureDefinition/Extension-Client-id`

3. **Treatment Function** (conditional)
   - For PIFU questionnaires only
   - System: `https://fhir.nhs.uk/StructureDefinition/Extension-Task-TreatmentFunction`

## Future Enhancements

The new Task structure enables:
- ✅ Appointment booking invites
- ✅ Pre-assessment questionnaires
- ✅ PIFU questionnaires
- 🔄 Referral action tasks (future)
- 🔄 Document review tasks (future)
- 🔄 Custom patient tasks (extensible via reasonCode)

## Migration Checklist

For NHS App and Consumer Implementations:
- [ ] Review and test new Task examples
- [ ] Update data models to support new fields (`intent`, `reasonCode`, `reasonReference`, `for`, `owner`)
- [ ] Implement logic to handle `reasonCode.system` for task type differentiation
- [ ] Handle optional fields appropriately (e.g., `focus` for incomplete booking invites)
- [ ] Add support for `statusReason` for rejection details
- [ ] Test rendering of both questionnaire and appointment booking tasks
- [ ] Maintain Questionnaire resource support during transition period
- [ ] Plan migration strategy for existing questionnaire implementations

## Questions & Clarifications

**Q: When will the Questionnaire resource be deprecated?**
A: No immediate deprecation. The Questionnaire resource will remain supported during a transition period (to be determined). We'll provide advance notice before any deprecation.

**Q: Do I need to update my system immediately?**
A: No. Existing implementations using Questionnaire continue to work. Adopt Task resource for new implementations or when ready to migrate.

**Q: How do I distinguish between task types?**
A: Use the `reasonCode.coding.system` field:
- Questionnaires: `Extension-Questionnaire-Type`
- Booking invites: `Extension-Task-Type`

**Q: What about linked appointments?**
A: Use the `focus` field to reference an appointment:
- For completed booking invites: `focus.reference` points to the booked appointment
- For questionnaires before appointment: `focus` may be empty or optional

**Q: Can I store custom data in Task?**
A: Yes, use extensions (array) to add custom fields following FHIR extension patterns.

---

**Document Version**: 1.0  
**Last Updated**: 2026-07-20  
**Status**: Implementation Complete
