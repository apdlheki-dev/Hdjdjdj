module.exports = {
  port: process.env.PORT || 3000,
  maxEmailsPerRequest: 100,
  concurrency: 4,

  // إعدادات فحص IMAP — تسجيل دخول فعلي
  imapTimeoutMs: 12000,
  imapPorts: [993, 143],

  // إعدادات فحص SMTP AUTH — بديل لو IMAP فشل
  smtpAuthTimeoutMs: 12000,
  smtpAuthPorts: [587, 465, 25],

  // hosts IMAP معروفة لمزودين بريطانيين
  imapHosts: {
    "blueyonder.co.uk": ["imap.virginmedia.com", "imap.blueyonder.co.uk"],
    "tiscali.co.uk": ["imap.talktalk.net", "imap.tiscali.co.uk"],
    "hotmail.co.uk": ["outlook.office365.com", "imap-mail.outlook.com"],
    "live.co.uk": ["outlook.office365.com", "imap-mail.outlook.com"],
    "outlook.co.uk": ["outlook.office365.com"],
    "yahoo.co.uk": ["imap.mail.yahoo.com"],
    "gmx.co.uk": ["imap.gmx.co.uk", "imap.gmx.net"],
    "btinternet.co.uk": ["mail.btinternet.com"],
    "googlemail.co.uk": ["imap.gmail.com"],
  },
};
