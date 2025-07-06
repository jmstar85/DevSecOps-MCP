// Vulnerable Dependencies Test Application
const express = require('express');
const lodash = require('lodash');
const moment = require('moment');
const request = require('request');
const handlebars = require('handlebars');
const minimist = require('minimist');
const axios = require('axios');

console.log('📦 Loading vulnerable dependencies for SCA testing...');

// Using vulnerable versions of popular packages
console.log('Express version:', require('express/package.json').version);
console.log('Lodash version:', require('lodash/package.json').version);
console.log('Moment version:', require('moment/package.json').version);
console.log('Request version:', require('request/package.json').version);
console.log('Handlebars version:', require('handlebars/package.json').version);

const app = express();

app.get('/', (req, res) => {
    res.json({
        message: 'SCA Test Application',
        dependencies: {
            express: require('express/package.json').version,
            lodash: require('lodash/package.json').version,
            moment: require('moment/package.json').version,
            request: require('request/package.json').version,
            handlebars: require('handlebars/package.json').version,
            minimist: require('minimist/package.json').version,
            axios: require('axios/package.json').version
        },
        note: 'These versions contain known vulnerabilities for testing purposes'
    });
});

module.exports = app;