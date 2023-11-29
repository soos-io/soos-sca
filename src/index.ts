#!/usr/bin/env node
import * as FileSystem from "fs";
import * as Glob from "glob";
import * as Path from "path";
import FormData from "form-data";
import {
  LogLevel,
  OnFailure,
  OutputFormat,
  PackageManagerType,
  SOOS_CONSTANTS,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  ensureEnumValue,
  ensureNonEmptyValue,
  getEnvVariable,
  obfuscateProperties,
  sleep,
  formatBytes,
} from "@soos-io/api-client/dist/utilities";
import StringUtilities from "@soos-io/api-client/dist/StringUtilities";
import { ArgumentParser } from "argparse";
import { CONSTANTS } from "./utils/constants";
import { exit } from "process";
import SOOSAnalysisApiClient, {
  IUploadManifestFilesResponse,
} from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import SOOSProjectsApiClient from "@soos-io/api-client/dist/api/SOOSProjectsApiClient";
import { getDirectoriesToExclude } from "./utils/utilities";

interface IManifestFile {
  packageManager: string;
  name: string;
  path: string;
}

interface SOOSSCAAnalysisArgs {
  apiKey: string;
  apiURL: string;
  appVersion: string;
  branchName: string;
  branchUri: string;
  buildUri: string;
  buildVersion: string;
  clientId: string;
  commitHash: string;
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  integrationName: string;
  integrationType: string;
  logLevel: LogLevel;
  onFailure: OnFailure;
  operatingEnvironment: string;
  outputFormat: OutputFormat;
  packageManagers: Array<string>;
  projectName: string;
  sarif: boolean;
  scriptVersion: string;
  sourceCodePath: string;
  verbose: boolean;
  workingDirectory: string;
}

class SOOSSCAAnalysis {
  constructor(private args: SOOSSCAAnalysisArgs) {}
  static parseArgs(): SOOSSCAAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS Sca" });

    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/containers",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });

    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
      type: (value: string) => {
        return ensureNonEmptyValue(value, "apiURL");
      },
    });

    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--branchName", {
      help: "The name of the branch from the SCM System.",
      required: false,
    });

    parser.add_argument("--branchURI", {
      help: "The URI to the branch from the SCM System.",
      required: false,
    });

    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      required: false,
    });

    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      required: false,
    });

    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/containers",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });

    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      required: false,
    });

    parser.add_argument("--directoriesToExclude", {
      help: "Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**",
      type: (value: string) => {
        return getDirectoriesToExclude(value.split(","));
      },
      default: CONSTANTS.SOOS.DEFAULT_DIRECTORIES_TO_EXCLUDE,
      required: false,
    });

    parser.add_argument("--filesToExclude", {
      help: "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt",
      type: (value: string) => {
        return value.split(",").map((pattern) => pattern.trim());
      },
      required: false,
    });

    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      required: false,
      default: CONSTANTS.SOOS.DEFAULT_INTEGRATION_TYPE,
    });

    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(LogLevel, value);
      },
    });

    parser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      default: OnFailure.Continue,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OnFailure, value);
      },
    });

    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      required: false,
    });

    parser.add_argument("--outputFormat", {
      help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OutputFormat, value);
      },
    });

    parser.add_argument("--packageManagers", {
      help: "A list of package managers, delimited by comma, to include when searching for manifest files.",
      required: false,
      default: [],
      type: (value: string) => {
        const values = value.split(",");
        values.map((value) => {
          return ensureEnumValue(PackageManagerType, value);
        });
        return values;
      },
    });

    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
      type: (value: string) => {
        return ensureNonEmptyValue(value, "projectName");
      },
    });

    parser.add_argument("--sarif", {
      help: "Generates SARIF report.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--scriptVersion", {
      required: false,
    });

    parser.add_argument("--sourceCodePath", {
      help: "Root path to begin recursive search for manifests.",
      default: process.cwd(),
      required: false,
    });

    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      default: false,
      required: false,
    });

    parser.add_argument("--workingDirectory", {
      help: "Absolute path where SOOS may write and read persistent files for the given build. eg Correct: /tmp/workspace/ | Incorrect: ./bin/start/",
      default: process.cwd(),
      required: false,
    });

    soosLogger.info("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let isDone = false;

    const soosAnalysisApiClient = new SOOSAnalysisApiClient(this.args.apiKey, this.args.apiURL);
    const soosProjectsApiClient = new SOOSProjectsApiClient(
      this.args.apiKey,
      this.args.apiURL.replace("api.", "api-projects.")
    );
    try {
      soosLogger.info("Starting SOOS SCA Analysis");
      soosLogger.info(`Creating scan for project '${this.args.projectName}'...`);
      soosLogger.info(`Branch Name: ${this.args.branchName}`);

      const result = await soosAnalysisApiClient.createScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branch: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: null,
        contributingDeveloperAudit: undefined,
        scanType: ScanType.SCA,
        toolName: null,
        toolVersion: null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;

      soosLogger.info(`Project Hash: ${projectHash}`);
      soosLogger.info(`Branch Hash: ${branchHash}`);
      soosLogger.info(`Scan Id: ${analysisId}`);
      soosLogger.info("Scan created successfully.");
      soosLogger.logLineSeparator();

      const supportedManifestsResponse = await soosAnalysisApiClient.getSupportedManifests({
        clientId: this.args.clientId,
      });

      const filteredPackageManagers =
        this.args.packageManagers.length === 0
          ? supportedManifestsResponse
          : supportedManifestsResponse.filter((packageManagerManifests) =>
              this.args.packageManagers.some((pm) =>
                StringUtilities.areEqual(pm, packageManagerManifests.packageManager, {
                  sensitivity: "base",
                })
              )
            );

      const settings = await soosProjectsApiClient.getProjectSettings({
        clientId: this.args.clientId,
        projectHash,
      });

      const manifestFiles = this.searchForManifestFiles({
        packageManagerManifests: filteredPackageManagers,
        useLockFile: settings.useLockFile ?? false,
      });

      if (manifestFiles.length === 0) {
        const errorMessage =
          "No valid manifests found, cannot continue. For more help, please visit https://kb.soos.io/help/error-no-valid-manifests-found";

        await soosAnalysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.SCA,
          scanId: analysisId,
          status: ScanStatus.Incomplete,
          message: errorMessage,
        });
        isDone = true;
        throw new Error(errorMessage);
      }

      const filesToUpload = manifestFiles.slice(0, SOOS_CONSTANTS.FileUploads.MaxManifests);
      const hasMoreThanMaximumManifests =
        manifestFiles.length > SOOS_CONSTANTS.FileUploads.MaxManifests;
      if (hasMoreThanMaximumManifests) {
        const filesToSkip = manifestFiles.slice(SOOS_CONSTANTS.FileUploads.MaxManifests);
        const filesDetectedString = StringUtilities.pluralizeTemplate(
          manifestFiles.length,
          "file was",
          "files were"
        );
        const filesSkippedString = StringUtilities.pluralizeTemplate(
          filesToSkip.length,
          "file",
          "files"
        );
        soosLogger.info(
          `The maximum number of manifest per scan is ${SOOS_CONSTANTS.FileUploads.MaxManifests}. ${filesDetectedString} detected, and ${filesSkippedString} will be not be uploaded. \n`,
          `The following manifests will not be included in the scan: \n`,
          filesToSkip.map((file) => `  "${file.name}": "${file.path}"`).join("\n")
        );
      }

      const manifestsByPackageManager = filesToUpload.reduce<Record<string, Array<IManifestFile>>>(
        (accumulator, file) => {
          const packageManagerFiles =
            (accumulator[file.packageManager] as Array<IManifestFile> | undefined) ?? [];
          return {
            ...accumulator,
            [file.packageManager]: packageManagerFiles.concat(file),
          };
        },
        {}
      );

      // note: assuming failure until proven otherwise
      let allUploadsFailed = true;

      for (const [packageManager, files] of Object.entries(manifestsByPackageManager)) {
        try {
          const manifestUploadResponse = await this.uploadManifestFilesByPackageManager({
            apiClient: soosAnalysisApiClient,
            clientId: this.args.clientId,
            projectHash,
            branchHash,
            analysisId,
            manifestFiles: files,
          });

          soosLogger.info(
            `${packageManager} Manifest Files: \n`,
            `  ${manifestUploadResponse.message} \n`,
            manifestUploadResponse.manifests
              ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
              .join("\n")
          );

          allUploadsFailed = false;
        } catch (e: unknown) {
          // NOTE: we continue on to the other package managers, but log it as a warning in the log
          const message = e instanceof Error ? e.message : (e as string);
          soosLogger.warn(message);
        }
      }

      if (allUploadsFailed) {
        await soosAnalysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.SCA,
          scanId: analysisId,
          status: ScanStatus.Incomplete,
          message: `Error uploading manifests.`,
        });
        isDone = true;
        throw new Error("Error uploading manifests.");
      }

      soosLogger.logLineSeparator();
      soosLogger.info("Starting SCA Analysis scan");
      await soosAnalysisApiClient.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisId,
      });
      soosLogger.info(
        `Analysis scan started successfully, to see the results visit: ${result.scanUrl}`
      );

      const scanStatus = await this.waitForScanToFinish({
        apiClient: soosAnalysisApiClient,
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
      });

      isDone = true;

      if (this.args.outputFormat !== undefined) {
        soosLogger.info(`Generating SARIF report  ${this.args.projectName}...`);
        const output = await soosAnalysisApiClient.getFormattedScanResult({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.SCA,
          scanId: analysisId,
          outputFormat: this.args.outputFormat,
        });
        soosLogger.info(`SARIF report generated successfully.`);
        if (output) {
          soosLogger.info(`Output ('${this.args.outputFormat}' format):`);
          soosLogger.info(JSON.stringify(output, null, 2));
          if (this.args.sourceCodePath) {
            soosLogger.info(
              `Writing SARIF report to ${this.args.sourceCodePath}/${CONSTANTS.FILES.SARIF}`
            );
            FileSystem.writeFileSync(
              `${this.args.workingDirectory}/${CONSTANTS.FILES.SARIF}`,
              JSON.stringify(output, null, 2)
            );
          }
        }
      }

      if (this.args.onFailure === OnFailure.Fail) {
        if (scanStatus === ScanStatus.FailedWithIssues) {
          soosLogger.info("Analysis complete - Failures reported");
          soosLogger.info("Failing the build.");
          process.exit(1);
        } else if (scanStatus === ScanStatus.Incomplete) {
          soosLogger.info(
            "Analysis Incomplete. It may have been cancelled or superseded by another scan."
          );
          soosLogger.info("Failing the build.");
          process.exit(1);
        } else if (scanStatus === ScanStatus.Error) {
          soosLogger.info("Analysis Error.");
          soosLogger.info("Failing the build.");
          process.exit(1);
        }
      }
    } catch (error) {
      if (projectHash && branchHash && analysisId && !isDone)
        await soosAnalysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.SCA,
          scanId: analysisId,
          status: ScanStatus.Error,
          message: `Error while performing scan.`,
        });
      soosLogger.error(error);
      exit(1);
    }
  }

  private async uploadManifestFilesByPackageManager({
    apiClient,
    clientId,
    projectHash,
    branchHash,
    analysisId,
    manifestFiles,
  }: {
    apiClient: SOOSAnalysisApiClient;
    clientId: string;
    projectHash: string;
    branchHash: string;
    analysisId: string;
    manifestFiles: Array<IManifestFile>;
  }): Promise<IUploadManifestFilesResponse> {
    const formData = manifestFiles.reduce((formDataAcc: FormData, manifest, index) => {
      const workingDirectory = process.env.SYSTEM_DEFAULTWORKINGDIRECTORY ?? "";
      const manifestParts = manifest.path.replace(workingDirectory, "").split(Path.sep);
      const parentFolder =
        manifestParts.length >= 2
          ? manifestParts.slice(0, manifestParts.length - 1).join(Path.sep)
          : "";
      const suffix = index > 0 ? index : "";
      const fileReadStream = FileSystem.createReadStream(manifest.path, {
        encoding: SOOS_CONSTANTS.FileUploads.Encoding,
      });
      formDataAcc.append(`file${suffix}`, fileReadStream);
      formDataAcc.append(`parentFolder${suffix}`, parentFolder);

      return formDataAcc;
    }, new FormData());

    const response = await apiClient.uploadManifestFiles({
      clientId,
      projectHash,
      branchHash,
      analysisId,
      manifestFiles: formData,
    });

    return response;
  }

  private searchForManifestFiles({
    packageManagerManifests,
    useLockFile,
  }: {
    packageManagerManifests: Array<{
      packageManager: string;
      manifests: Array<{
        pattern: string;
        isLockFile: boolean;
      }>;
    }>;
    useLockFile: boolean;
  }): Array<IManifestFile> {
    const currentDirectory = process.cwd();
    soosLogger.info(
      `Setting current working directory to project path '${this.args.sourceCodePath}'.`
    );
    process.chdir(this.args.sourceCodePath);
    soosLogger.info(
      `Lock file setting is ${
        useLockFile ? "on, ignoring non-lock files" : "off, ignoring lock files"
      }.`
    );
    const manifestFiles = packageManagerManifests.reduce<Array<IManifestFile>>(
      (accumulator, packageManagerManifests) => {
        const matches = packageManagerManifests.manifests
          .filter((manifest) => useLockFile === manifest.isLockFile) // filter manifests by lock file
          .map((manifest) => {
            const manifestGlobPattern = manifest.pattern.startsWith(".")
              ? `*${manifest.pattern}` // ends with
              : manifest.pattern; // wildcard match

            const pattern = `**/${manifestGlobPattern}`;
            soosLogger.info(`Files to exclude: ${this.args.filesToExclude}`);
            soosLogger.info(`Directories to exclude: ${this.args.directoriesToExclude}`);
            const files = Glob.sync(pattern, {
              ignore: [...(this.args.filesToExclude || []), ...this.args.directoriesToExclude],
              nocase: true,
            });

            // This is needed to resolve the path as an absolute opposed to trying to open the file at current directory.
            const absolutePathFiles = files.map((x) => Path.resolve(x));

            const matchingFilesMessage = `${absolutePathFiles.length} files found matching pattern '${pattern}'.`;
            if (absolutePathFiles.length > 0) {
              soosLogger.info(matchingFilesMessage);
            } else {
              soosLogger.verboseInfo(matchingFilesMessage);
            }

            return absolutePathFiles;
          });

        return accumulator.concat(
          matches.flat().map((filePath): IManifestFile => {
            const filename = Path.basename(filePath);
            const fileStats = FileSystem.statSync(filePath);
            const fileSize = formatBytes(fileStats.size);
            soosLogger.info(
              `Found manifest file '${filename}' (${fileSize}) at location '${filePath}'.`
            );
            return {
              packageManager: packageManagerManifests.packageManager,
              name: filename,
              path: filePath,
            };
          })
        );
      },
      []
    );

    process.chdir(currentDirectory);
    soosLogger.info(`Setting current working directory back to '${currentDirectory}'.\n`);
    soosLogger.info(`${manifestFiles.length} manifest files found.`);

    return manifestFiles;
  }

  private async waitForScanToFinish({
    apiClient,
    scanStatusUrl,
    scanUrl,
  }: {
    apiClient: SOOSAnalysisApiClient;
    scanStatusUrl: string;
    scanUrl: string;
  }): Promise<ScanStatus> {
    const scanStatus = await apiClient.getScanStatus({
      scanStatusUrl,
    });

    if (!scanStatus.isComplete) {
      soosLogger.info(`${StringUtilities.fromCamelToTitleCase(scanStatus.status)}...`);
      await sleep(CONSTANTS.STATUS.DELAY_TIME);
      return await this.waitForScanToFinish({ apiClient, scanStatusUrl, scanUrl });
    }

    if (scanStatus.errors.length > 0) {
      soosLogger.group("Errors:");
      soosLogger.warn(JSON.stringify(scanStatus.errors, null, 2));
      soosLogger.groupEnd();
    }

    if (scanStatus.isSuccess) {
      scanStatus.vulnerabilities > 0 || scanStatus.violations > 0;
    }

    let statusMessage = `Scan ${scanStatus.isSuccess ? "passed" : "failed"}`;
    if (scanStatus.hasIssues) {
      const vulnerabilities = StringUtilities.pluralizeTemplate(
        scanStatus.vulnerabilities,
        "vulnerability",
        "vulnerabilities"
      );

      const violations = StringUtilities.pluralizeTemplate(
        scanStatus.violations,
        "violation",
        "violations"
      );

      statusMessage = statusMessage.concat(
        `${scanStatus.isSuccess ? ", but had" : " because of"} ${vulnerabilities} and ${violations}`
      );
    }

    const resultMessage = `${statusMessage}. View the results at: ${scanUrl}`;
    soosLogger.info(resultMessage);
    return scanStatus.status;
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS SCA Analysis");
    soosLogger.logLineSeparator();
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      soosLogger.info("Configuration read");
      soosLogger.verboseDebug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2
        )
      );
      ensureNonEmptyValue(args.clientId, "clientId");
      ensureNonEmptyValue(args.apiKey, "apiKey");
      soosLogger.logLineSeparator();
      const soosSCAAnalysis = new SOOSSCAAnalysis(args);
      await soosSCAAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      exit(1);
    }
  }
}

SOOSSCAAnalysis.createAndRun();
