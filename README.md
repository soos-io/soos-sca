# [SOOS Core SCA](https://soos.io/sca-product)

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/products/sca). [Generate and ingest SBOMs](https://soos.io/products/sbom-manager). [Export reports](https://kb.soos.io/help/soos-reports-for-export) to industry standards. Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/products/dast) against your web apps or APIs. [Scan your Docker containers](https://soos.io/products/containers) for vulnerabilities. Check your source code for issues with [SAST Analysis](https://soos.io/products/sast).

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## soos-sca
NPM package to run SOOS Core SCA

## Supported Languages and Package Managers
Our full list of supported manifest formats can be found [here](https://kb.soos.io/help/soos-languages-supported).

## Need an Account?
**Visit [soos.io](https://app.soos.io/register) to create your trial account.**

## Requirements
  - [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
  
## Installation

### Globally
run `npm i -g @soos-io/soos-sca@latest`

Then Run `soos-sca` from any terminal and add the parameters you want.

### Locally
run `npm install --prefix ./soos @soos-io/soos-sca`

Then run from the same terminal `node ./soos/node_modules/@soos-io/soos-sca/bin/index.js`

## Running the Script
See [Script Knowlege Base Documentation](https://github.com/soos-io/kb-docs/blob/main/SCA/Script.md)

### Linux Shell Script Example
See [Linux GitHub Gist](https://gist.githubusercontent.com/soostech/bf4fe3c320f7457a81f2e48ebe057aa5/raw/7fcba97f88c524b2d1e3eddf2c29de52af13a0c4/soos_sca.sh)

### Windows CMD Script Example
See [Windows Batch File Gist](https://gist.githubusercontent.com/soostech/37134fb636da3246d275b2ee220669c1/raw/0ab31b1c50869d8e8061deee4fa04e8ff7169f77/soos_sca.bat)

### Client Parameters

| Argument | Default | Description |
| --- | --- | --- |
| `--apiKey` |  | SOOS API Key - get yours from [SOOS Integration](https://app.soos.io/integrate/sca). Uses `SOOS_API_KEY` env value if present.  
| `--branchName` |  | The name of the branch from the SCM System. |
| `--branchURI` |  | The URI to the branch from the SCM System. |
| `--buildURI` |  | URI to CI build info. |
| `--buildVersion` |  | Version of application build artifacts. |
| `--clientId` |  | SOOS Client ID - get yours from [SOOS Integration](https://app.soos.io/integrate/sca). Uses `SOOS_API_CLIENT` env value if present. |
| `--commitHash` |  | The commit hash value from the SCM System. |
| `--directoriesToExclude` | `**/node_modules/**, "**/bin/**", "**/obj/**", "**/lib/**` | Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/** |
| `--filesToExclude` |  | Listing of files or patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt |
| `--logLevel` | `INFO` | Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL. |
| `--onFailure` | `continue_on_failure` | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure. |
| `--operatingEnvironment` |  | Set Operating environment for information purposes only. |
| `--outputFormat` |  | Output format for vulnerabilities: only the value SARIF is available at the moment. |
| `--packageManagers` |  | A list of package managers, delimited by comma, to include when searching for manifest files. |
| `--projectName` |  | Project Name - this is what will be displayed in the SOOS app. |
| `--sarif` |  | Generates SARIF report. |
| `--scriptVersion` |  | None provided. |
| `--sourceCodePath` | `process.cwd()` | Root path to begin recursive search for manifests. |
| `--verbose` | `false` | Enable verbose logging. |
| `--workingDirectory` | `process.cwd()` | Absolute path where SOOS may write and read persistent files for the given build. eg Correct: /tmp/workspace/ | Incorrect: ./bin/start/ |

## Feedback and Support
See [SOOS Knowledge Base](https://kb.soos.io/help)