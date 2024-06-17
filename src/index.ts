#!/usr/bin/env node
import * as Path from "path";
import { version } from "../package.json";
import {
  IntegrationName,
  IntegrationType,
  OutputFormat,
  PackageManagerType,
  SOOS_CONSTANTS,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
  StringUtilities,
} from "@soos-io/api-client/dist/utilities";
import { SOOS_SCA_CONSTANTS } from "./constants";
import { exit } from "process";
import { IUploadManifestFilesResponse } from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import AnalysisService, { IManifestFile } from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { removeDuplicates } from "./utilities";
import { FileMatchTypeEnum } from "@soos-io/api-client/dist/enums";

interface SOOSSCAAnalysisArgs extends IBaseScanArguments {
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  outputFormat: OutputFormat;
  packageManagers?: Array<string>;
  sourceCodePath: string;
  workingDirectory: string;
  fileMatchType: FileMatchTypeEnum;
}

class SOOSSCAAnalysis {
  constructor(private args: SOOSSCAAnalysisArgs) {}

  static parseArgs(): SOOSSCAAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosSca,
      IntegrationType.Script,
      ScanType.SCA,
      version,
    );

    analysisArgumentParser.addBaseScanArguments();

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

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--outputFormat",
      OutputFormat,
      {
        help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
        required: false,
      },
    );

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--fileMatchType",
      FileMatchTypeEnum,
      {
        help: "The method to use to locate files for scanning, looking for manifest files and/or files to hash.",
        required: false,
        default: FileMatchTypeEnum.Manifest,
      },
    );

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--packageManagers",
      {
        [PackageManagerType.CFamily]: PackageManagerType.CFamily,
        [PackageManagerType.Dart]: PackageManagerType.Dart,
        [PackageManagerType.Erlang]: PackageManagerType.Erlang,
        [PackageManagerType.Go]: PackageManagerType.Go,
        [PackageManagerType.Homebrew]: PackageManagerType.Homebrew,
        [PackageManagerType.Java]: PackageManagerType.Java,
        [PackageManagerType.NPM]: PackageManagerType.NPM,
        [PackageManagerType.NuGet]: PackageManagerType.NuGet,
        [PackageManagerType.Php]: PackageManagerType.Php,
        [PackageManagerType.Python]: PackageManagerType.Python,
        [PackageManagerType.Ruby]: PackageManagerType.Ruby,
        [PackageManagerType.Rust]: PackageManagerType.Rust,
      },
      {
        help: "A list of package managers, delimited by comma, to include when searching for manifest files.",
        required: false,
        default: [],
      },
      true,
    );

    analysisArgumentParser.argumentParser.add_argument("--sourceCodePath", {
      help: "Root path to begin recursive search for manifests.",
      default: process.cwd(),
      required: false,
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
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
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

      // TODO: call const manifestsAndHashableFiles = await analysisService.findManifestsAndHashableFiles()
      const manifestsAndHashableFiles = await analysisService.findManifestsAndHashableFiles({
        clientId: this.args.clientId,
        projectHash,
        filesToExclude: this.args.filesToExclude,
        directoriesToExclude: this.args.directoriesToExclude,
        sourceCodePath: this.args.sourceCodePath,
        packageManagers: this.args.packageManagers ?? [],
        fileMatchType: this.args.fileMatchType,
      });

      const manifestFiles = manifestsAndHashableFiles.manifestFiles ?? [];
      const soosHashesManifests = manifestsAndHashableFiles.hashManifests ?? [];

      let errorMessage = null;

      if (this.args.fileMatchType === FileMatchTypeEnum.Manifest && manifestFiles.length === 0) {
        errorMessage =
          "No valid files found, cannot continue. For more help, please visit https://kb.soos.io/help/error-no-valid-manifests-found";
      }

      if (
        this.args.fileMatchType === FileMatchTypeEnum.FileHash &&
        soosHashesManifests.length === 0
      ) {
        errorMessage =
          "No valid files to hash were found, cannot continue. For more help, please visit https://kb.soos.io/help/error-no-valid-files-to-hash-found";
      }

      if (
        this.args.fileMatchType === FileMatchTypeEnum.ManifestAndFileHash &&
        soosHashesManifests.length === 0 &&
        manifestFiles.length === 0
      ) {
        errorMessage =
          "No valid files found, cannot continue. For more help, please visit https://kb.soos.io/help/error-no-valid-manifests-found and https://kb.soos.io/help/error-no-valid-files-to-hash-found";
      }

      if (errorMessage) {
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
          // TODO: PA-14211 can we add the soos_hashes.json directly
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
          workingDirectory: this.args.workingDirectory,
        });
      }

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
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
      soosLogger.always(`${error} - exit 1`);
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
      Path.resolve(this.args.sourceCodePath),
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
      soosLogger.logLineSeparator();
      const soosSCAAnalysis = new SOOSSCAAnalysis(args);
      await soosSCAAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }
}

SOOSSCAAnalysis.createAndRun();
