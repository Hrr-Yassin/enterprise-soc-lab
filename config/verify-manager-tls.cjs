// Wazuh Dashboard 4.14.10 creates its Manager API HTTPS agent with
// rejectUnauthorized=false. Require the project CA for that one service.
'use strict';

const fs = require('node:fs');
const https = require('node:https');
const tls = require('node:tls');

const ca = fs.readFileSync('/usr/share/wazuh-dashboard/certs/root-ca.pem');
const connect = https.Agent.prototype.createConnection;

https.Agent.prototype.createConnection = function connectWithLabCa(options, callback) {
  const names = [options.hostname, options.host, options.servername];
  if (Number(options.port) === 55000 && names.includes('wazuh.manager')) {
    options = {
      ...options,
      ca,
      servername: 'wazuh.manager',
      checkServerIdentity: tls.checkServerIdentity,
      rejectUnauthorized: true,
    };
  }
  return connect.call(this, options, callback);
};
