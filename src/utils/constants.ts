export const CONSTANTS = {
  FILES: {
    SARIF_OUTPUT: "results.sarif",
  },
  SOOS: {
    ENVIRONMENT_VARIABLES: {
      API_KEY: "SOOS_API_KEY",
      CLIENT_ID: "SOOS_CLIENT_ID",
    },
    DEFAULT_INTEGRATION_TYPE: "Script",
    DEFAULT_DIRECTORIES_TO_EXCLUDE: ["**/node_modules/**", "**/bin/**", "**/obj/**", "**/lib/**"],
  },
  STATUS: {
    DELAY_TIME: 5000,
    MAX_ATTEMPTS: 10,
  },
};
