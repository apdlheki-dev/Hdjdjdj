// config.js
module.exports = {
  port: process.env.PORT || 3000,

  // الدومينات المسموح فحصها — بالضبط اللي طلبتها
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

  // الدومينات اللي عندها مزودي بريد كبار — فحص SMTP عليها غير مجدي وغالباً محظور
  // نعرض تحذير بدل ما نحاول
  bigProviderDomains: [
    "hotmail.co.uk", "live.co.uk", "yahoo.co.uk",
    "blueyonder.co.uk", "tiscali.co.uk",
  ],

  // حدود الحماية من الإساءة
  maxEmailsPerRequest: 500,
  maxRequestsPerMinutePerIp: 10,
  smtpTimeoutMs: 8000,
  smtpPort: 25,
  heloHost: "mail.localhost", // غيّره لدومينك الحقيقي في الإنتاج

  // مصدر الإرسال للـ MAIL FROM — إيميل وهمي مقبول
  mailFrom: "noreply@example.com",
};
