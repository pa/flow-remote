// Copy to config.js. On GCP, fill it from the skoop identity resource's
// outputs. For a local run against `MAILBOX_DEV_AUTH=1`, set devEmail and
// leave firebase empty.
export default {
  firebase: { apiKey: "", authDomain: "", projectId: "", appId: "" },
  tenantId: "",
  devEmail: "",
};
