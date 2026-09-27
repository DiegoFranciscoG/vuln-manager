using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace VulnManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "asp_net_roles",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    normalized_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    concurrency_stamp = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_roles", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "asp_net_users",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    normalized_user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    normalized_email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    email_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                    password_hash = table.Column<string>(type: "text", nullable: true),
                    security_stamp = table.Column<string>(type: "text", nullable: true),
                    concurrency_stamp = table.Column<string>(type: "text", nullable: true),
                    phone_number = table.Column<string>(type: "text", nullable: true),
                    phone_number_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                    two_factor_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    lockout_end = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    lockout_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    access_failed_count = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    actor_type = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    actor_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    action = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    entity_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    entity_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    details = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_log", x => x.id);
                    table.CheckConstraint("ck_audit_log_actor_type", "actor_type IN ('USER', 'API_KEY', 'SYSTEM')");
                });

            migrationBuilder.CreateTable(
                name: "components",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    purl = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    @namespace = table.Column<string>(name: "namespace", type: "character varying(255)", maxLength: 255, nullable: true),
                    name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    version = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    vulns_checked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_components", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "kev_entries",
                columns: table => new
                {
                    cve_id = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    vendor_project = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    vulnerability_name = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    date_added = table.Column<DateOnly>(type: "date", nullable: false),
                    due_date = table.Column<DateOnly>(type: "date", nullable: true),
                    short_description = table.Column<string>(type: "text", nullable: false),
                    required_action = table.Column<string>(type: "text", nullable: false),
                    known_ransomware_campaign_use = table.Column<bool>(type: "boolean", nullable: false),
                    forensic_triage = table.Column<bool>(type: "boolean", nullable: true),
                    cwes = table.Column<string[]>(type: "text[]", nullable: false),
                    catalog_version = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    removed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_kev_entries", x => x.cve_id);
                });

            migrationBuilder.CreateTable(
                name: "priority_rules",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    version = table.Column<int>(type: "integer", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    notes = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    epss_percentile_threshold = table.Column<decimal>(type: "numeric(4,3)", precision: 4, scale: 3, nullable: false),
                    high_impact_min_cvss = table.Column<decimal>(type: "numeric(3,1)", precision: 3, scale: 1, nullable: false),
                    unknown_severity_as = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    ssvc_active_counts_as_exploited = table.Column<bool>(type: "boolean", nullable: false),
                    rules = table.Column<string>(type: "jsonb", nullable: false),
                    sla_policy = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    sla_severity_days = table.Column<string>(type: "jsonb", nullable: false),
                    fix_on_upgrade_days = table.Column<int>(type: "integer", nullable: true),
                    created_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_priority_rules", x => x.id);
                    table.CheckConstraint("ck_priority_rules_epss_threshold", "epss_percentile_threshold > 0 AND epss_percentile_threshold <= 1");
                    table.CheckConstraint("ck_priority_rules_high_impact", "high_impact_min_cvss >= 0 AND high_impact_min_cvss <= 10");
                    table.CheckConstraint("ck_priority_rules_sla_policy", "sla_policy IN ('BOD2604', 'SEVERITY')");
                    table.CheckConstraint("ck_priority_rules_unknown", "unknown_severity_as IN ('LOW', 'HIGH')");
                });

            migrationBuilder.CreateTable(
                name: "sync_runs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    source = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    trigger = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    finished_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    items_requested = table.Column<int>(type: "integer", nullable: false),
                    items_updated = table.Column<int>(type: "integer", nullable: false),
                    http_requests = table.Column<int>(type: "integer", nullable: false),
                    http_throttled = table.Column<int>(type: "integer", nullable: false),
                    watermark = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    error_message = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sync_runs", x => x.id);
                    table.CheckConstraint("ck_sync_runs_source", "source IN ('OSV', 'KEV', 'EPSS', 'CVE', 'NVD')");
                    table.CheckConstraint("ck_sync_runs_status", "status IN ('RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')");
                    table.CheckConstraint("ck_sync_runs_trigger", "trigger IN ('SCHEDULED', 'MANUAL', 'SBOM_IMPORT', 'STARTUP', 'EXTERNAL')");
                });

            migrationBuilder.CreateTable(
                name: "vulnerabilities",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    external_id = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    source = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    cve_id = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    aliases = table.Column<string[]>(type: "text[]", nullable: false),
                    summary = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    details = table.Column<string>(type: "character varying(20000)", maxLength: 20000, nullable: true),
                    cvss_version = table.Column<string>(type: "character varying(3)", maxLength: 3, nullable: true),
                    cvss_vector = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    cvss_score = table.Column<decimal>(type: "numeric(3,1)", precision: 3, scale: 1, nullable: true),
                    cvss_source = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    severity = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    epss_score = table.Column<decimal>(type: "numeric(6,5)", precision: 6, scale: 5, nullable: true),
                    epss_percentile = table.Column<decimal>(type: "numeric(6,5)", precision: 6, scale: 5, nullable: true),
                    epss_date = table.Column<DateOnly>(type: "date", nullable: true),
                    in_kev = table.Column<bool>(type: "boolean", nullable: false),
                    ssvc_exploitation = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    ssvc_automatable = table.Column<bool>(type: "boolean", nullable: true),
                    ssvc_technical_impact = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    published_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    modified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    withdrawn_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_synced_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    epss_synced_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cve_synced_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    nvd_synced_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_vulnerabilities", x => x.id);
                    table.CheckConstraint("ck_vulnerabilities_cve_id", "cve_id IS NULL OR cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'");
                    table.CheckConstraint("ck_vulnerabilities_cvss_score", "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)");
                    table.CheckConstraint("ck_vulnerabilities_cvss_source", "cvss_source IS NULL OR cvss_source IN ('OSV', 'CNA', 'NVD')");
                    table.CheckConstraint("ck_vulnerabilities_cvss_version", "cvss_version IS NULL OR cvss_version IN ('3.0', '3.1', '4.0')");
                    table.CheckConstraint("ck_vulnerabilities_epss_percentile", "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)");
                    table.CheckConstraint("ck_vulnerabilities_epss_score", "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)");
                    table.CheckConstraint("ck_vulnerabilities_severity", "severity IN ('UNKNOWN', 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')");
                    table.CheckConstraint("ck_vulnerabilities_source", "source IN ('OSV')");
                    table.CheckConstraint("ck_vulnerabilities_ssvc_exploitation", "ssvc_exploitation IS NULL OR ssvc_exploitation IN ('NONE', 'POC', 'ACTIVE')");
                    table.CheckConstraint("ck_vulnerabilities_ssvc_technical_impact", "ssvc_technical_impact IS NULL OR ssvc_technical_impact IN ('PARTIAL', 'TOTAL')");
                });

            migrationBuilder.CreateTable(
                name: "asp_net_role_claims",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    role_id = table.Column<string>(type: "text", nullable: false),
                    claim_type = table.Column<string>(type: "text", nullable: true),
                    claim_value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_role_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_asp_net_role_claims_asp_net_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "asp_net_roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "asp_net_user_claims",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    user_id = table.Column<string>(type: "text", nullable: false),
                    claim_type = table.Column<string>(type: "text", nullable: true),
                    claim_value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_user_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_asp_net_user_claims_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "asp_net_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "asp_net_user_logins",
                columns: table => new
                {
                    login_provider = table.Column<string>(type: "text", nullable: false),
                    provider_key = table.Column<string>(type: "text", nullable: false),
                    provider_display_name = table.Column<string>(type: "text", nullable: true),
                    user_id = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_user_logins", x => new { x.login_provider, x.provider_key });
                    table.ForeignKey(
                        name: "fk_asp_net_user_logins_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "asp_net_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "asp_net_user_roles",
                columns: table => new
                {
                    user_id = table.Column<string>(type: "text", nullable: false),
                    role_id = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_user_roles", x => new { x.user_id, x.role_id });
                    table.ForeignKey(
                        name: "fk_asp_net_user_roles_asp_net_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "asp_net_roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_asp_net_user_roles_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "asp_net_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "asp_net_user_tokens",
                columns: table => new
                {
                    user_id = table.Column<string>(type: "text", nullable: false),
                    login_provider = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asp_net_user_tokens", x => new { x.user_id, x.login_provider, x.name });
                    table.ForeignKey(
                        name: "fk_asp_net_user_tokens_asp_net_users_user_id",
                        column: x => x.user_id,
                        principalTable: "asp_net_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "component_vulnerabilities",
                columns: table => new
                {
                    component_id = table.Column<Guid>(type: "uuid", nullable: false),
                    vulnerability_id = table.Column<Guid>(type: "uuid", nullable: false),
                    fixed_versions = table.Column<string[]>(type: "text[]", nullable: false),
                    fix_available = table.Column<bool>(type: "boolean", nullable: false),
                    suggested_fix_version = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    first_matched_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_matched_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_component_vulnerabilities", x => new { x.component_id, x.vulnerability_id });
                    table.ForeignKey(
                        name: "fk_component_vulnerabilities_components_component_id",
                        column: x => x.component_id,
                        principalTable: "components",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_component_vulnerabilities_vulnerabilities_vulnerability_id",
                        column: x => x.vulnerability_id,
                        principalTable: "vulnerabilities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "alerts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    finding_id = table.Column<Guid>(type: "uuid", nullable: true),
                    type = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    message = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    dedup_key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    acknowledged_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    acknowledged_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    webhook_delivered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_alerts", x => x.id);
                    table.CheckConstraint("ck_alerts_type", "type IN ('NEW_P1', 'NEW_KEV_MATCH', 'SLA_DUE_SOON', 'SLA_OVERDUE', 'FORENSIC_TRIAGE')");
                });

            migrationBuilder.CreateTable(
                name: "finding_status_history",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    finding_id = table.Column<Guid>(type: "uuid", nullable: false),
                    from_status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    to_status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    justification = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    vex_statement_id = table.Column<Guid>(type: "uuid", nullable: true),
                    change_source = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    changed_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    changed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_finding_status_history", x => x.id);
                    table.CheckConstraint("ck_finding_status_history_from", "from_status IS NULL OR from_status IN ('NEW', 'ACCEPTED', 'MITIGATED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'FIXED')");
                    table.CheckConstraint("ck_finding_status_history_source", "change_source IN ('USER', 'SBOM_IMPORT', 'VEX', 'SYNC', 'EXPIRY')");
                    table.CheckConstraint("ck_finding_status_history_to", "to_status IN ('NEW', 'ACCEPTED', 'MITIGATED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'FIXED')");
                });

            migrationBuilder.CreateTable(
                name: "findings",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    component_id = table.Column<Guid>(type: "uuid", nullable: false),
                    vulnerability_id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    status_reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    risk_accepted_until = table.Column<DateOnly>(type: "date", nullable: true),
                    vex_statement_id = table.Column<Guid>(type: "uuid", nullable: true),
                    priority_level = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    priority_rule_id = table.Column<Guid>(type: "uuid", nullable: true),
                    priority_explanation = table.Column<string>(type: "jsonb", nullable: false),
                    sla_policy = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    sla_row = table.Column<int>(type: "integer", nullable: true),
                    sla_days = table.Column<int>(type: "integer", nullable: true),
                    sla_started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    sla_due_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    sla_explanation = table.Column<string>(type: "jsonb", nullable: false),
                    forensic_triage_required = table.Column<bool>(type: "boolean", nullable: false),
                    first_detected_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resolved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    detected_in_import_id = table.Column<Guid>(type: "uuid", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_findings", x => x.id);
                    table.CheckConstraint("ck_findings_accepted_until", "status <> 'ACCEPTED' OR risk_accepted_until IS NOT NULL");
                    table.CheckConstraint("ck_findings_not_affected_vex", "status <> 'NOT_AFFECTED' OR vex_statement_id IS NOT NULL");
                    table.CheckConstraint("ck_findings_priority_level", "priority_level IN ('P1', 'P2', 'P3', 'P4')");
                    table.CheckConstraint("ck_findings_sla_policy", "sla_policy IN ('BOD2604', 'SEVERITY')");
                    table.CheckConstraint("ck_findings_sla_row", "sla_row IS NULL OR (sla_row BETWEEN 1 AND 16)");
                    table.CheckConstraint("ck_findings_status", "status IN ('NEW', 'ACCEPTED', 'MITIGATED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'FIXED')");
                    table.ForeignKey(
                        name: "fk_findings_components_component_id",
                        column: x => x.component_id,
                        principalTable: "components",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_findings_priority_rules_priority_rule_id",
                        column: x => x.priority_rule_id,
                        principalTable: "priority_rules",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_findings_vulnerabilities_vulnerability_id",
                        column: x => x.vulnerability_id,
                        principalTable: "vulnerabilities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "project_api_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    key_prefix = table.Column<string>(type: "character(8)", fixedLength: true, maxLength: 8, nullable: false),
                    key_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_project_api_keys", x => x.id);
                    table.CheckConstraint("ck_project_api_keys_hash_length", "octet_length(key_hash) = 32");
                });

            migrationBuilder.CreateTable(
                name: "projects",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    repository_url = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    exposure = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    environment = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    asset_type = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    current_sbom_import_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    archived_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_projects", x => x.id);
                    table.CheckConstraint("ck_projects_asset_type", "asset_type IN ('APPLICATION', 'SERVER', 'NETWORK_DEVICE')");
                    table.CheckConstraint("ck_projects_environment", "environment IN ('PRODUCTION', 'DEVELOPMENT')");
                    table.CheckConstraint("ck_projects_exposure", "exposure IN ('INTERNAL', 'PUBLIC')");
                    table.CheckConstraint("ck_projects_repository_url", "repository_url IS NULL OR repository_url LIKE 'https://%'");
                });

            migrationBuilder.CreateTable(
                name: "sbom_imports",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    format = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    spec_version = table.Column<string>(type: "character varying(5)", maxLength: 5, nullable: false),
                    bom_serial_number = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    bom_version = table.Column<int>(type: "integer", nullable: true),
                    source = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    source_ref = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    file_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    sha256 = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    size_bytes = table.Column<int>(type: "integer", nullable: false),
                    component_count = table.Column<int>(type: "integer", nullable: false),
                    skipped_count = table.Column<int>(type: "integer", nullable: false),
                    status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    error_message = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    imported_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    imported_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    processed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sbom_imports", x => x.id);
                    table.CheckConstraint("ck_sbom_imports_format", "format IN ('CYCLONEDX_JSON')");
                    table.CheckConstraint("ck_sbom_imports_sha256", "sha256 ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("ck_sbom_imports_size", "size_bytes > 0 AND size_bytes <= 10485760");
                    table.CheckConstraint("ck_sbom_imports_source", "source IN ('API', 'UPLOAD')");
                    table.CheckConstraint("ck_sbom_imports_status", "status IN ('PENDING', 'PROCESSED', 'FAILED')");
                    table.ForeignKey(
                        name: "fk_sbom_imports_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "sbom_components",
                columns: table => new
                {
                    sbom_import_id = table.Column<Guid>(type: "uuid", nullable: false),
                    component_id = table.Column<Guid>(type: "uuid", nullable: false),
                    bom_ref = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    scope = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sbom_components", x => new { x.sbom_import_id, x.component_id });
                    table.CheckConstraint("ck_sbom_components_scope", "scope IS NULL OR scope IN ('required', 'optional', 'excluded')");
                    table.ForeignKey(
                        name: "fk_sbom_components_components_component_id",
                        column: x => x.component_id,
                        principalTable: "components",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_sbom_components_sbom_imports_sbom_import_id",
                        column: x => x.sbom_import_id,
                        principalTable: "sbom_imports",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "vex_statements",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    vulnerability_ref = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    component_purl = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    justification_scheme = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    justification = table.Column<string>(type: "character varying(60)", maxLength: 60, nullable: true),
                    impact_statement = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    action_statement = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    cdx_state = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: true),
                    cdx_response = table.Column<string[]>(type: "text[]", nullable: true),
                    source = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    source_import_id = table.Column<Guid>(type: "uuid", nullable: true),
                    author = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_vex_statements", x => x.id);
                    table.CheckConstraint("ck_vex_statements_affected", "status <> 'AFFECTED' OR action_statement IS NOT NULL");
                    table.CheckConstraint("ck_vex_statements_justification", "justification IS NULL OR (justification_scheme = 'CISA' AND justification IN ('component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist')) OR (justification_scheme = 'CYCLONE_DX' AND justification IN ('code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'))");
                    table.CheckConstraint("ck_vex_statements_not_affected", "status <> 'NOT_AFFECTED' OR justification IS NOT NULL OR impact_statement IS NOT NULL");
                    table.CheckConstraint("ck_vex_statements_source", "source IN ('MANUAL', 'CYCLONE_DX_VEX')");
                    table.CheckConstraint("ck_vex_statements_status", "status IN ('NOT_AFFECTED', 'AFFECTED', 'FIXED', 'UNDER_INVESTIGATION')");
                    table.ForeignKey(
                        name: "fk_vex_statements_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_vex_statements_sbom_imports_source_import_id",
                        column: x => x.source_import_id,
                        principalTable: "sbom_imports",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_alerts_dedup_key",
                table: "alerts",
                column: "dedup_key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_alerts_finding_id",
                table: "alerts",
                column: "finding_id");

            migrationBuilder.CreateIndex(
                name: "ix_alerts_project_id_acknowledged_at",
                table: "alerts",
                columns: new[] { "project_id", "acknowledged_at" });

            migrationBuilder.CreateIndex(
                name: "ix_asp_net_role_claims_role_id",
                table: "asp_net_role_claims",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "asp_net_roles",
                column: "normalized_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_asp_net_user_claims_user_id",
                table: "asp_net_user_claims",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_asp_net_user_logins_user_id",
                table: "asp_net_user_logins",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_asp_net_user_roles_role_id",
                table: "asp_net_user_roles",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "asp_net_users",
                column: "normalized_email");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "asp_net_users",
                column: "normalized_user_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_entity_type_entity_id",
                table: "audit_log",
                columns: new[] { "entity_type", "entity_id" });

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_occurred_at",
                table: "audit_log",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "ix_component_vulnerabilities_vulnerability_id",
                table: "component_vulnerabilities",
                column: "vulnerability_id");

            migrationBuilder.CreateIndex(
                name: "ix_components_purl",
                table: "components",
                column: "purl",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_components_vulns_checked_at",
                table: "components",
                column: "vulns_checked_at");

            migrationBuilder.CreateIndex(
                name: "ix_finding_status_history_finding_id_changed_at",
                table: "finding_status_history",
                columns: new[] { "finding_id", "changed_at" });

            migrationBuilder.CreateIndex(
                name: "ix_findings_component_id",
                table: "findings",
                column: "component_id");

            migrationBuilder.CreateIndex(
                name: "ix_findings_detected_in_import_id",
                table: "findings",
                column: "detected_in_import_id");

            migrationBuilder.CreateIndex(
                name: "ix_findings_priority_rule_id",
                table: "findings",
                column: "priority_rule_id");

            migrationBuilder.CreateIndex(
                name: "ix_findings_project_id_component_id_vulnerability_id",
                table: "findings",
                columns: new[] { "project_id", "component_id", "vulnerability_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_findings_project_id_status_priority_level",
                table: "findings",
                columns: new[] { "project_id", "status", "priority_level" });

            migrationBuilder.CreateIndex(
                name: "ix_findings_sla_due_at",
                table: "findings",
                column: "sla_due_at",
                filter: "status = 'NEW'");

            migrationBuilder.CreateIndex(
                name: "ix_findings_vex_statement_id",
                table: "findings",
                column: "vex_statement_id");

            migrationBuilder.CreateIndex(
                name: "ix_findings_vulnerability_id",
                table: "findings",
                column: "vulnerability_id");

            migrationBuilder.CreateIndex(
                name: "ix_priority_rules_is_active",
                table: "priority_rules",
                column: "is_active",
                unique: true,
                filter: "is_active");

            migrationBuilder.CreateIndex(
                name: "ix_priority_rules_version",
                table: "priority_rules",
                column: "version",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_project_api_keys_key_prefix",
                table: "project_api_keys",
                column: "key_prefix",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_project_api_keys_project_id",
                table: "project_api_keys",
                column: "project_id");

            migrationBuilder.CreateIndex(
                name: "ix_projects_current_sbom_import_id",
                table: "projects",
                column: "current_sbom_import_id");

            migrationBuilder.CreateIndex(
                name: "ix_sbom_components_component_id",
                table: "sbom_components",
                column: "component_id");

            migrationBuilder.CreateIndex(
                name: "ix_sbom_imports_project_id_sha256",
                table: "sbom_imports",
                columns: new[] { "project_id", "sha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_sync_runs_source_started_at",
                table: "sync_runs",
                columns: new[] { "source", "started_at" });

            migrationBuilder.CreateIndex(
                name: "ux_sync_runs_single_running",
                table: "sync_runs",
                column: "source",
                unique: true,
                filter: "status = 'RUNNING'");

            migrationBuilder.CreateIndex(
                name: "ix_vex_statements_project_id_vulnerability_ref",
                table: "vex_statements",
                columns: new[] { "project_id", "vulnerability_ref" },
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_vex_statements_source_import_id",
                table: "vex_statements",
                column: "source_import_id");

            migrationBuilder.CreateIndex(
                name: "ix_vulnerabilities_aliases",
                table: "vulnerabilities",
                column: "aliases")
                .Annotation("Npgsql:IndexMethod", "gin");

            migrationBuilder.CreateIndex(
                name: "ix_vulnerabilities_cve_id",
                table: "vulnerabilities",
                column: "cve_id");

            migrationBuilder.CreateIndex(
                name: "ix_vulnerabilities_external_id",
                table: "vulnerabilities",
                column: "external_id",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "fk_alerts_findings_finding_id",
                table: "alerts",
                column: "finding_id",
                principalTable: "findings",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_alerts_projects_project_id",
                table: "alerts",
                column: "project_id",
                principalTable: "projects",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_finding_status_history_findings_finding_id",
                table: "finding_status_history",
                column: "finding_id",
                principalTable: "findings",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_projects_project_id",
                table: "findings",
                column: "project_id",
                principalTable: "projects",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_sbom_imports_detected_in_import_id",
                table: "findings",
                column: "detected_in_import_id",
                principalTable: "sbom_imports",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_vex_statements_vex_statement_id",
                table: "findings",
                column: "vex_statement_id",
                principalTable: "vex_statements",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_project_api_keys_projects_project_id",
                table: "project_api_keys",
                column: "project_id",
                principalTable: "projects",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "fk_projects_sbom_imports_current_sbom_import_id",
                table: "projects",
                column: "current_sbom_import_id",
                principalTable: "sbom_imports",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            // Project names are unique regardless of case.
            migrationBuilder.Sql("CREATE UNIQUE INDEX ux_projects_name_lower ON projects (lower(name));");

            // Audit trail and status history are append-only. Retention purge sets a transaction-local flag.
            migrationBuilder.Sql("""
                CREATE FUNCTION prevent_append_only_mutation() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    IF TG_OP = 'DELETE' AND current_setting('vulnmanager.allow_retention_purge', true) = 'on' THEN
                        RETURN OLD;
                    END IF;
                    RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
                END;
                $$;
                """);
            migrationBuilder.Sql("CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION prevent_append_only_mutation();");
            migrationBuilder.Sql("CREATE TRIGGER finding_status_history_append_only BEFORE UPDATE OR DELETE ON finding_status_history FOR EACH ROW EXECUTE FUNCTION prevent_append_only_mutation();");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS finding_status_history_append_only ON finding_status_history;");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS prevent_append_only_mutation();");
            migrationBuilder.Sql("DROP INDEX IF EXISTS ux_projects_name_lower;");

            migrationBuilder.DropForeignKey(
                name: "fk_sbom_imports_projects_project_id",
                table: "sbom_imports");

            migrationBuilder.DropTable(
                name: "alerts");

            migrationBuilder.DropTable(
                name: "asp_net_role_claims");

            migrationBuilder.DropTable(
                name: "asp_net_user_claims");

            migrationBuilder.DropTable(
                name: "asp_net_user_logins");

            migrationBuilder.DropTable(
                name: "asp_net_user_roles");

            migrationBuilder.DropTable(
                name: "asp_net_user_tokens");

            migrationBuilder.DropTable(
                name: "audit_log");

            migrationBuilder.DropTable(
                name: "component_vulnerabilities");

            migrationBuilder.DropTable(
                name: "finding_status_history");

            migrationBuilder.DropTable(
                name: "kev_entries");

            migrationBuilder.DropTable(
                name: "project_api_keys");

            migrationBuilder.DropTable(
                name: "sbom_components");

            migrationBuilder.DropTable(
                name: "sync_runs");

            migrationBuilder.DropTable(
                name: "asp_net_roles");

            migrationBuilder.DropTable(
                name: "asp_net_users");

            migrationBuilder.DropTable(
                name: "findings");

            migrationBuilder.DropTable(
                name: "components");

            migrationBuilder.DropTable(
                name: "priority_rules");

            migrationBuilder.DropTable(
                name: "vex_statements");

            migrationBuilder.DropTable(
                name: "vulnerabilities");

            migrationBuilder.DropTable(
                name: "projects");

            migrationBuilder.DropTable(
                name: "sbom_imports");
        }
    }
}
