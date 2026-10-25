import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "csv-parse/sync";
import { resolveIdentityForRequest } from "./identityResolver.ts";
import type {
  AuditDataset,
  DeletionRequest,
  DeletionRule,
  EvidenceFile,
  IdentityAuditEntry,
  RequestIntentClassification,
  SystemActivity,
  UserIdentity,
} from "./types.ts";
import { classifyDeletionIntent } from "./intentClassifier.ts";

const REQUEST_COLUMNS = [
  "case_id",
  "email",
  "requested_at",
  "reported_status",
  "reported_at",
  "audit_at",
  "request_text",
] as const;

const EXPECTED_REQUEST_COUNT = 518;

const IDENTITY_COLUMNS = [
  "user_id",
  "name",
  "email",
  "phone",
  "email_hash",
  "updated_at",
] as const;

const IDENTITY_AUDIT_COLUMNS = [
  "audit_id",
  "user_id",
  "event_time",
  "field_name",
  "old_value",
  "new_value",
] as const;

const ACTIVITY_COLUMNS = [
  "activity_id",
  "event_time",
  "event_type",
  "source_system",
  "target_system",
  "resource_id",
  "reported_result",
  "details",
] as const;

const DELETION_RULE_COLUMNS = [
  "rule_id",
  "data_category",
  "condition",
  "required_action",
] as const;

const EVIDENCE_FILE_COLUMNS = [
  "file_id",
  "file_path",
  "origin",
  "captured_at",
] as const;

function parseCsvTable<T>(
  csvText: string,
  sourceName: string,
  expectedColumns: readonly string[],
): T[] {
  const rows = parse(csvText, {
    bom: true,
    columns: true,
    skip_empty_lines: true,
  }) as Record<string, unknown>[];

  const firstRow = rows[0];
  if (!firstRow) {
    throw new Error(`${sourceName} has a header but no data rows.`);
  }

  const actualColumns = Object.keys(firstRow);
  const columnsMatch =
    actualColumns.length === expectedColumns.length &&
    expectedColumns.every((column, index) => actualColumns[index] === column);

  if (!columnsMatch) {
    throw new Error(
      `Unexpected columns in ${sourceName}: ${actualColumns.join(",")}`,
    );
  }

  for (const [index, row] of rows.entries()) {
    const missingColumn = expectedColumns.find(
      (column) => typeof row[column] !== "string",
    );
    if (missingColumn) {
      throw new Error(
        `${sourceName} row ${index + 2} is missing a string value for ${missingColumn}.`,
      );
    }
  }

  return rows as T[];
}

async function readCsvTable<T>(
  datasetDirectory: string,
  fileName: string,
  expectedColumns: readonly string[],
): Promise<T[]> {
  const csvText = await readFile(resolve(datasetDirectory, fileName), "utf8");
  return parseCsvTable<T>(csvText, fileName, expectedColumns);
}

async function loadAuditDataset(repositoryRoot: string): Promise<AuditDataset> {
  const datasetDirectory = resolve(repositoryRoot, "dataset");
  const [deletionRequests, identities, identityHistory, activity, deletionRules, evidenceFiles] =
    await Promise.all([
      readCsvTable<DeletionRequest>(datasetDirectory, "deletion_requests.csv", REQUEST_COLUMNS),
      readCsvTable<UserIdentity>(datasetDirectory, "user_identities.csv", IDENTITY_COLUMNS),
      readCsvTable<IdentityAuditEntry>(datasetDirectory, "user_audit_log.csv", IDENTITY_AUDIT_COLUMNS),
      readCsvTable<SystemActivity>(datasetDirectory, "system_activity.csv", ACTIVITY_COLUMNS),
      readCsvTable<DeletionRule>(datasetDirectory, "deletion_rules.csv", DELETION_RULE_COLUMNS),
      readCsvTable<EvidenceFile>(datasetDirectory, "evidence_files.csv", EVIDENCE_FILE_COLUMNS),
    ]);

  if (deletionRequests.length !== EXPECTED_REQUEST_COUNT) {
    throw new Error(
      `Expected ${EXPECTED_REQUEST_COUNT} deletion requests, found ${deletionRequests.length}.`,
    );
  }

  return {
    deletionRequests,
    identities,
    identityHistory,
    activity,
    deletionRules,
    evidenceFiles,
  };
}

async function main(): Promise<void> {
  const sourceDirectory = dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = resolve(sourceDirectory, "../..");
  const dataset = await loadAuditDataset(repositoryRoot);
  const intentCounts = { deletion: 0, other: 0 };
  const identityCounts = { unique: 0, ambiguous: 0, unresolved: 0 };

  for (const request of dataset.deletionRequests) {
    const intent: RequestIntentClassification = classifyDeletionIntent(
      request.request_text,
    );
    if (intent.intent === "OTHER_REQUEST") {
      intentCounts.other += 1;
      continue;
    }

    intentCounts.deletion += 1;
    const resolution = resolveIdentityForRequest(
      request.email,
      request.audit_at,
      dataset.identities,
      dataset.identityHistory,
    );

    if (resolution.candidates.length === 1) {
      identityCounts.unique += 1;
    } else if (resolution.candidates.length > 1) {
      identityCounts.ambiguous += 1;
    } else {
      identityCounts.unresolved += 1;
    }
  }

  console.log(
    [
      `Loaded ${dataset.deletionRequests.length} deletion requests`,
      `${dataset.identities.length} current identities`,
      `${dataset.identityHistory.length} identity history entries`,
      `${dataset.activity.length} activity events`,
      `${dataset.deletionRules.length} deletion rules`,
      `${dataset.evidenceFiles.length} evidence manifest entries.`,
    ].join("; "),
  );
  console.log(
    `Request intent: ${intentCounts.deletion} deletion, ${intentCounts.other} other.`,
  );
  console.log(
    `Identity matches: ${identityCounts.unique} unique, ${identityCounts.ambiguous} ambiguous, ${identityCounts.unresolved} unresolved.`,
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Audit agent could not start: ${message}`);
  process.exitCode = 1;
});
