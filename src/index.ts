#!/usr/bin/env node
import { version } from "../package.json";
import {
  IntegrationName,
  IntegrationType,
  PackageManagerType,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
  isScanDone,
  obfuscateCommandLine,
  reassembleCommandLine,
} from "@soos-io/api-client/dist/utilities";
import { SOOS_SCA_CONSTANTS } from "./constants";
import { exit } from "process";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { removeDuplicates } from "./utilities";
import {
  AttributionFileTypeEnum,
  AttributionFormatEnum,
  FileMatchTypeEnum,
} from "@soos-io/api-client/dist/enums";

interface ISCAAnalysisArgs extends IBaseScanArguments {
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  packageManagers?: Array<string>;
  sourceCodePath: string;
  workingDirectory: string;
  outputDirectory: string;
  fileMatchType: FileMatchTypeEnum;
}

class SOOSSCAAnalysis {
  constructor(private args: ISCAAnalysisArgs) {}

  static parseArgs(): ISCAAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosSca,
      IntegrationType.Script,
      ScanType.SCA,
      version,
    );

    analysisArgumentParser.addArgument(
      "directoriesToExclude",
      "Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**",
      {
        argParser: (value: string) => {
          return removeDuplicates(value.split(",").map((pattern) => pattern.trim()));
        },
        defaultValue: SOOS_SCA_CONSTANTS.DefaultDirectoriesToExclude,
      },
    );

    analysisArgumentParser.addArgument(
      "filesToExclude",
      "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt",
      {
        argParser: (value: string) => {
          return value.split(",").map((pattern) => pattern.trim());
        },
        defaultValue: [],
      },
    );

    analysisArgumentParser.addEnumArgument(
      "fileMatchType",
      FileMatchTypeEnum,
      "The method to use to locate files for scanning, looking for manifest files and/or files to hash.",
      {
        defaultValue: FileMatchTypeEnum.Manifest,
      },
    );

    analysisArgumentParser.addEnumArgument(
      "packageManagers",
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
        [PackageManagerType.Swift]: PackageManagerType.Swift,
        [PackageManagerType.Unity]: PackageManagerType.Unity,
      },
      "A list of package managers, delimited by comma, to include when searching for manifest files.",
      {
        allowMultipleValues: true,
      },
    );

    analysisArgumentParser.addArgument(
      "sourceCodePath",
      "Root path to begin recursive search for manifests.",
      {
        defaultValue: process.cwd(),
      },
    );

    analysisArgumentParser.addArgument(
      "workingDirectory",
      "Absolute path where SOOS may write and read persistent files for the given build. eg Correct: /tmp/workspace/ | Incorrect: ./bin/start/",
      {
        defaultValue: process.cwd(),
      },
    );

    analysisArgumentParser.addArgument(
      "outputDirectory",
      "Absolute path where SOOS will write exported reports and SBOMs. eg Correct: /out/sbom/ | Incorrect: ./out/sbom/",
      {
        defaultValue: process.cwd(),
      },
    );

    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SCA;
    const analysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;
    let scanStatus: ScanStatus | undefined;

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
        contributingDeveloperAudit: [
          {
            contributingDeveloperId: this.args.contributingDeveloperId,
            source: this.args.contributingDeveloperSource,
            sourceName: this.args.contributingDeveloperSourceName,
          },
        ],
        scanType,
        commandLine:
          process.argv.length > 2
            ? obfuscateCommandLine(
                reassembleCommandLine(process.argv.slice(2)),
                SOOS_SCA_CONSTANTS.ObfuscatedArguments.map((a) => `--${a}`),
              )
            : null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      const { manifestFiles, hashManifests } = await analysisService.findManifestsAndHashableFiles({
        clientId: this.args.clientId,
        projectHash,
        filesToExclude: this.args.filesToExclude,
        directoriesToExclude: this.args.directoriesToExclude,
        sourceCodePath: this.args.sourceCodePath,
        packageManagers: this.args.packageManagers ?? [],
        fileMatchType: this.args.fileMatchType,
      });

      const { exitCode } = await analysisService.addManifestsAndHashableFilesToScan({
        clientId: this.args.clientId,
        projectHash: result.projectHash,
        branchHash: result.branchHash,
        analysisId: result.analysisId,
        scanType,
        scanStatusUrl: result.scanStatusUrl,
        fileMatchType: this.args.fileMatchType,
        manifestFiles,
        hashManifests,
      });
      if (exitCode !== 0) {
        exit(exitCode);
      }

      await analysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: result.analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      scanStatus = await analysisService.waitForScanToFinish({
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (
        isScanDone(scanStatus) &&
        this.args.exportFormat !== AttributionFormatEnum.Unknown &&
        this.args.exportFileType !== AttributionFileTypeEnum.Unknown
      ) {
        await analysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          analysisId: result.analysisId,
          format: this.args.exportFormat,
          fileType: this.args.exportFileType,
          includeDependentProjects: false,
          includeOriginalSbom: false,
          includeVulnerabilities: false,
          workingDirectory: this.args.outputDirectory,
        });
      }

      const { exitCode: analysisExitCode, message } = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${message} - exit ${analysisExitCode}`);
      exit(analysisExitCode);
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : (e as string);
      if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus)))
        await analysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          analysisId: analysisId,
          status: ScanStatus.Error,
          message: `Error while performing scan: ${errorMessage}`,
          scanStatusUrl,
        });
      soosLogger.error(errorMessage);
      soosLogger.always(`Error: ${errorMessage} - exit 1`);
      exit(1);
    }
  }

  static async createAndRun(): Promise<void> {
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.always("Starting SOOS SCA Analysis");
      soosLogger.debug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2,
        ),
      );

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
