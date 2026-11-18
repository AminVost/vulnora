-- Vulnora Security Intelligence — initial schema. UUIDs are server-generated.
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS workspaces (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL,
 created_by UUID NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS memberships (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','security_manager','developer','viewer')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(workspace_id,user_id)
);
CREATE TABLE IF NOT EXISTS integrations (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 provider TEXT NOT NULL, external_id TEXT, status TEXT NOT NULL DEFAULT 'pending',
 config JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS repositories (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 integration_id UUID REFERENCES integrations(id), url TEXT NOT NULL, default_branch TEXT,
 last_commit TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(workspace_id,url)
);
CREATE TABLE IF NOT EXISTS projects (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 repository_id UUID REFERENCES repositories(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 repository_url TEXT, repository_branch TEXT NOT NULL DEFAULT 'HEAD', source_type TEXT NOT NULL DEFAULT 'manual',
 criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN('low','medium','high','critical')),
 internet_exposed BOOLEAN NOT NULL DEFAULT false, environment TEXT NOT NULL DEFAULT 'unknown',
 last_scanned_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace_id);
CREATE TABLE IF NOT EXISTS project_environments (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 name TEXT NOT NULL, exposed BOOLEAN, notes TEXT, UNIQUE(project_id,name)
);
CREATE TABLE IF NOT EXISTS project_releases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 environment_id UUID REFERENCES project_environments(id) ON DELETE CASCADE,
 version TEXT NOT NULL, git_sha TEXT, deployed_at TIMESTAMPTZ, provenance TEXT NOT NULL DEFAULT 'manual',
 verified BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS dependency_snapshots (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 git_sha TEXT, origin TEXT NOT NULL, source_type TEXT NOT NULL,
 captured_at TIMESTAMPTZ NOT NULL DEFAULT now(), package_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS packages (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), ecosystem TEXT NOT NULL, name TEXT NOT NULL,
 UNIQUE(ecosystem,name)
);
CREATE TABLE IF NOT EXISTS package_versions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), package_id UUID NOT NULL REFERENCES packages(id),
 version TEXT NOT NULL, UNIQUE(package_id,version)
);
CREATE TABLE IF NOT EXISTS dependencies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 snapshot_id UUID REFERENCES dependency_snapshots(id) ON DELETE SET NULL,
 package_id UUID REFERENCES packages(id), package_version_id UUID REFERENCES package_versions(id),
 ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
 direct BOOLEAN NOT NULL DEFAULT false, source_file TEXT NOT NULL,
 source_type TEXT NOT NULL, current BOOLEAN NOT NULL DEFAULT true,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id,ecosystem,name,version,source_file)
);
CREATE INDEX IF NOT EXISTS idx_deps_project ON dependencies(project_id,current);
CREATE INDEX IF NOT EXISTS idx_deps_package ON dependencies(ecosystem,name);
CREATE TABLE IF NOT EXISTS dependency_relations (
 parent_dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
 child_dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
 relationship TEXT NOT NULL DEFAULT 'depends_on', PRIMARY KEY(parent_dependency_id,child_dependency_id)
);
CREATE TABLE IF NOT EXISTS vulnerability_advisories (
 id TEXT PRIMARY KEY, summary TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL DEFAULT 'unknown' CHECK(severity IN ('critical','high','medium','low','unknown')),
 cvss_score NUMERIC(4,1), cvss_vector TEXT, source TEXT NOT NULL DEFAULT 'OSV',
 aliases TEXT[] NOT NULL DEFAULT '{}', kev BOOLEAN, epss NUMERIC(8,7),
 modified_at TIMESTAMPTZ, fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 raw JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS advisory_aliases (
 alias TEXT NOT NULL, advisory_id TEXT NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
 PRIMARY KEY(alias,advisory_id)
);
CREATE TABLE IF NOT EXISTS affected_version_ranges (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), advisory_id TEXT NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
 ecosystem TEXT, package_name TEXT, range_data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
 advisory_id TEXT NOT NULL REFERENCES vulnerability_advisories(id),
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','triaged','in_progress','ready_for_verification','resolved','risk_accepted','false_positive','reopened')),
 priority TEXT NOT NULL DEFAULT 'unknown', risk_score INTEGER, risk_reason TEXT,
 assignee_id UUID REFERENCES users(id), due_at TIMESTAMPTZ, closure_reason TEXT,
 first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 resolved_at TIMESTAMPTZ, UNIQUE(project_id,dependency_id,advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_workspace_status ON findings(workspace_id,status);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE TABLE IF NOT EXISTS scan_jobs (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 requested_by UUID REFERENCES users(id), status TEXT NOT NULL DEFAULT 'queued',
 packages_checked INTEGER NOT NULL DEFAULT 0, findings_new INTEGER NOT NULL DEFAULT 0,
 error TEXT, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status,created_at);
CREATE TABLE IF NOT EXISTS scan_results (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
 dependency_id UUID REFERENCES dependencies(id), advisory_id TEXT REFERENCES vulnerability_advisories(id),
 result TEXT NOT NULL, checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS remediation_tasks (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', recommended_version TEXT,
 assignee_id UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS test_evidence (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 author_id UUID NOT NULL REFERENCES users(id), evidence_url TEXT, notes TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS risk_acceptances (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 accepted_by UUID NOT NULL REFERENCES users(id), reason TEXT NOT NULL,
 expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS comments (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 author_id UUID NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notifications (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id UUID REFERENCES users(id), title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
 read_at TIMESTAMPTZ, fingerprint TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(workspace_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 actor_id UUID REFERENCES users(id), action TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
 before JSONB, after JSONB, reason TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_workspace_date ON audit_events(workspace_id,created_at DESC);
CREATE TABLE IF NOT EXISTS sla_policies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
 deadline_days INTEGER NOT NULL CHECK (deadline_days>0), UNIQUE(workspace_id,severity)
);
