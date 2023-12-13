#!/usr/bin/env node
import * as FileSystem from "fs";
import * as Glob from "glob";
import * as Path from "path";
import { version } from "../package.json";
import {
  IntegrationName,
  IntegrationType,
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
  obfuscateProperties,
  formatBytes,
  verifyScanStatus,
} from "@soos-io/api-client/dist/utilities";
import StringUtilities from "@soos-io/api-client/dist/StringUtilities";
import { SOOS_SCA_CONSTANTS } from "./constants";
import { exit } from "process";
import { IUploadManifestFilesResponse } from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { removeDuplicates } from "./utilities";

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
  contributingDeveloperId: string;
  contributingDeveloperSource: string;
  contributingDeveloperSourceName: string;
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  integrationName: IntegrationName;
  integrationType: IntegrationType;
  logLevel: LogLevel;
  onFailure: OnFailure;
  operatingEnvironment: string;
  outputFormat: OutputFormat;
  packageManagers: Array<string>;
  projectName: string;
  scriptVersion: string;
  sourceCodePath: string;
  verbose: boolean;
  workingDirectory: string;
}

class SOOSSCAAnalysis {
  constructor(private args: SOOSSCAAnalysisArgs) {}

  static parseArgs(): SOOSSCAAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.SCA);

    analysisArgumentParser.addBaseScanArguments(
      IntegrationName.SoosSast,
      IntegrationType.Script,
      version,
    );

    analysisArgumentParser.argumentParser.add_argument("--directoriesToExclude", {
      help: "Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**",
      type: (value: string) => {
        return removeDuplicates(value.split(",").map((pattern) => pattern.trim()));
      },
      default: SOOS_SCA_CONSTANTS.DefaultDirectoriesToExclude,
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--filesToExclude", {
      help: "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt",
      type: (value: string) => {
        return value.split(",").map((pattern) => pattern.trim());
      },
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      default: OnFailure.Continue,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OnFailure, value);
      },
    });

    analysisArgumentParser.argumentParser.add_argument("--outputFormat", {
      help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OutputFormat, value);
      },
    });

    analysisArgumentParser.argumentParser.add_argument("--packageManagers", {
      help: "A list of package managers, delimited by comma, to include when searching for manifest files.",
      required: false,
      default: [],
      type: (value: string) => {
        if (value.length === 0) return [];
        const values = value.split(",");
        values.map((value) => {
          return ensureEnumValue(PackageManagerType, value);
        });
        return values;
      },
    });

    analysisArgumentParser.argumentParser.add_argument("--workingDirectory", {
      help: "Absolute path where SOOS may write and read persistent files for the given build. eg Correct: /tmp/workspace/ | Incorrect: ./bin/start/",
      default: process.cwd(),
      required: false,
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SCA;
    const analysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;

    try {
      const result = await analysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        branchName: this.args.branchName,
        commitHash: this.args.commitHash,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        integrationType: this.args.integrationType,
        appVersion: this.args.appVersion,
        scriptVersion: this.args.scriptVersion,
        contributingDeveloperAudit:
          !this.args.contributingDeveloperId ||
          !this.args.contributingDeveloperSource ||
          !this.args.contributingDeveloperSourceName
            ? []
            : [
                {
                  contributingDeveloperId: this.args.contributingDeveloperId,
                  source: this.args.contributingDeveloperSource,
                  sourceName: this.args.contributingDeveloperSourceName,
                },
              ],
        scanType,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      soosLogger.logLineSeparator();

      const supportedManifestsResponse =
        await analysisService.analysisApiClient.getSupportedManifests({
          clientId: this.args.clientId,
        });

      const filteredPackageManagers =
        this.args.packageManagers.length === 0
          ? supportedManifestsResponse
          : supportedManifestsResponse.filter((packageManagerManifests) =>
              this.args.packageManagers.some((pm) =>
                StringUtilities.areEqual(pm, packageManagerManifests.packageManager, {
                  sensitivity: "base",
                }),
              ),
            );

      const settings = await analysisService.projectsApiClient.getProjectSettings({
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
        await analysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          analysisId: analysisId,
          status: ScanStatus.Incomplete,
          message: errorMessage,
          scanStatusUrl: result.scanStatusUrl,
        });
        exit(1);
      }

      const filesToUpload = manifestFiles.slice(0, SOOS_CONSTANTS.FileUploads.MaxManifests);
      const hasMoreThanMaximumManifests =
        manifestFiles.length > SOOS_CONSTANTS.FileUploads.MaxManifests;
      if (hasMoreThanMaximumManifests) {
        const filesToSkip = manifestFiles.slice(SOOS_CONSTANTS.FileUploads.MaxManifests);
        const filesDetectedString = StringUtilities.pluralizeTemplate(
          manifestFiles.length,
          "file was",
          "files were",
        );
        const filesSkippedString = StringUtilities.pluralizeTemplate(filesToSkip.length, "file");
        soosLogger.info(
          `The maximum number of manifest per scan is ${SOOS_CONSTANTS.FileUploads.MaxManifests}. ${filesDetectedString} detected, and ${filesSkippedString} will be not be uploaded. \n`,
          `The following manifests will not be included in the scan: \n`,
          filesToSkip.map((file) => `  "${file.name}": "${file.path}"`).join("\n"),
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
        {},
      );

      let allUploadsFailed = true;
      for (const [packageManager, files] of Object.entries(manifestsByPackageManager)) {
        try {
          const manifestUploadResponse = await this.uploadManifestFiles({
            analysisService,
            clientId: this.args.clientId,
            projectHash,
            branchHash,
            analysisId,
            manifestFiles: files.map((f) => f.path),
            hasMoreThanMaximumManifests,
          });

          soosLogger.info(
            `${packageManager} Manifest Files: \n`,
            `  ${manifestUploadResponse.message} \n`,
            manifestUploadResponse.manifests
              ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
              .join("\n"),
          );

          allUploadsFailed = false;
        } catch (e: unknown) {
          // NOTE: we continue on to the other package managers
          soosLogger.warn(e instanceof Error ? e.message : (e as string));
        }
      }

      if (allUploadsFailed) {
        await analysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          analysisId: analysisId,
          status: ScanStatus.Incomplete,
          message: `Error uploading manifests.`,
          scanStatusUrl: result.scanStatusUrl,
        });
        exit(1);
      }

      soosLogger.logLineSeparator();
      await analysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: result.analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      const scanStatus = await analysisService.waitForScanToFinish({
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (this.args.outputFormat !== undefined) {
        await analysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          scanType,
          analysisId: result.analysisId,
          outputFormat: this.args.outputFormat,
          sourceCodePath: this.args.sourceCodePath,
          workingDirectory: this.args.workingDirectory,
        });
      }

      const exitWithError = verifyScanStatus(scanStatus);

      if (this.args.onFailure === OnFailure.Fail && exitWithError) {
        exit(1);
      }
    } catch (error) {
      if (projectHash && branchHash && analysisId)
        await analysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          analysisId: analysisId,
          status: ScanStatus.Error,
          message: "Error while performing scan.",
          scanStatusUrl,
        });
      soosLogger.error(error);
      exit(1);
    }
  }

  private async uploadManifestFiles({
    analysisService,
    clientId,
    projectHash,
    branchHash,
    analysisId,
    manifestFiles,
    hasMoreThanMaximumManifests,
  }: {
    analysisService: AnalysisService;
    clientId: string;
    projectHash: string;
    branchHash: string;
    analysisId: string;
    manifestFiles: Array<string>;
    hasMoreThanMaximumManifests: boolean;
  }): Promise<IUploadManifestFilesResponse> {
    const formData = await analysisService.getAnalysisFilesAsFormData(
      manifestFiles,
      this.args.sourceCodePath,
    );

    const response = await analysisService.analysisApiClient.uploadManifestFiles({
      clientId,
      projectHash,
      branchHash,
      analysisId,
      manifestFiles: formData,
      hasMoreThanMaximumManifests,
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
      `Setting current working directory to project path '${this.args.sourceCodePath}'.`,
    );
    process.chdir(this.args.sourceCodePath);
    soosLogger.info(
      `Lock file setting is ${
        useLockFile ? "on, ignoring non-lock files" : "off, ignoring lock files"
      }.`,
    );
    const manifestFiles = packageManagerManifests.reduce<Array<IManifestFile>>(
      (accumulator, packageManagerManifests) => {
        const matches = packageManagerManifests.manifests
          .filter((manifest) => useLockFile === manifest.isLockFile)
          .map((manifest) => {
            const manifestGlobPattern = manifest.pattern.startsWith(".")
              ? `*${manifest.pattern}` // ends with
              : manifest.pattern; // wildcard match

            const pattern = `**/${manifestGlobPattern}`;
            const files = Glob.sync(pattern, {
              ignore: [
                ...(this.args.filesToExclude || []),
                ...this.args.directoriesToExclude,
                SOOS_SCA_CONSTANTS.SoosPackageDirToExclude,
              ],
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
              `Found manifest file '${filename}' (${fileSize}) at location '${filePath}'.`,
            );
            return {
              packageManager: packageManagerManifests.packageManager,
              name: filename,
              path: filePath,
            };
          }),
        );
      },
      [],
    );

    process.chdir(currentDirectory);
    soosLogger.info(`Setting current working directory back to '${currentDirectory}'.\n`);
    soosLogger.info(`${manifestFiles.length} manifest files found.`);

    return manifestFiles;
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
          2,
        ),
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
