// config.js
module.exports = {
  port: process.env.PORT || 3000,

  allowedDomains: [
    "blueyonder.co.uk",
    "tiscali.co.uk",
    "excelsiorcarsandcourier.co.uk",
    "doctors.org.uk",
    "hotmail.co.uk",
    "live.co.uk",
    "yahoo.co.uk",
    "gov.uk",
    "ac.uk",
  ],

  bigProviderDomains: [
    "hotmail.co.uk", "live.co.uk", "yahoo.co.uk",
    "blueyonder.co.uk", "tiscali.co.uk",
  ],

  maxEmailsPerRequest: 500,
  maxRequestsPerMinutePerIp: 10,
  smtpTimeoutMs: 8000,
  smtpPort: 25,
  heloHost: "mail.localhost",
  mailFrom: "noreply@example.com",
};
