// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
// Planted Google Apps Script issues for the bundled aisa-gs rules.

// POSITIVE: hardcoded secret (use PropertiesService instead)
var API_KEY = "AKf9x72Kd0plQ2zR8vLmN4ts";

function doGet(e) {
  // POSITIVE: HtmlService output from request input (XSS)
  var out = HtmlService.createHtmlOutput("<b>Hi " + e.parameter.name + "</b>");
  // POSITIVE: setXFrameOptionsMode(ALLOWALL) disables clickjacking protection
  out.setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  return out;
}

function doPost(e) {
  // POSITIVE: UrlFetchApp to a request-controlled URL (SSRF)
  var res = UrlFetchApp.fetch(e.parameter.url);
  // POSITIVE: relying on getActiveUser for auth (empty for anonymous web apps)
  var who = Session.getActiveUser().getEmail();
  return ContentService.createTextOutput(res.getContentText());
}

// POSITIVE: getEffectiveUser returns the deployer, not the caller (auth misuse)
function whoami() {
  return Session.getEffectiveUser().getEmail();
}

// POSITIVE: public Drive sharing (ANYONE_WITH_LINK)
function publish(file) {
  file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
}

// POSITIVE: UrlFetchApp to a URL read from Script Properties with no host allow-list
function callWebhook() {
  return UrlFetchApp.fetch(PropertiesService.getScriptProperties().getProperty("WEBHOOK_URL"));
}

// NEGATIVE: secret from PropertiesService must NOT fire hardcoded-secret
function safeKey() {
  return PropertiesService.getScriptProperties().getProperty("API_KEY");
}

// NEGATIVE: fetch to a constant URL must NOT fire SSRF
function health() {
  return UrlFetchApp.fetch("https://api.example.com/health");
}

// NEGATIVE: private sharing must NOT fire drive-anyone-sharing
function lockDown(file) {
  file.setSharing(DriveApp.Access.PRIVATE, DriveApp.Permission.NONE);
}
