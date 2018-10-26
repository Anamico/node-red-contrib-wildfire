'use strict';

var async = require('async');
var request = require('request');

module.exports = function(RED) {

    function Service(config) {
        RED.nodes.createNode(this, config);

        var node = this;

        this.samples = function (params, callback) {

            if (!config.server) {
                callback(new Error('Missing Appliance Hostname/IP'));
                return;
            }
            const server = config.server.trim().toLowerCase();
            if (server == 'wildfire.paloaltonetworks.com') {
                callback(new Error('Cloud Retrieval not Supported, Use your appliance address'));
                return;
            }

            if (!config.apikey) {
                callback(new Error('Missing Apikey'));
                return;
            }

            const body = Object.assign({}, params, {
                apikey: config.apikey
            });
            if (!body.date) {
                callback(new Error('Missing Date'));
                return;
            }

            const uri = (config.apikey == 'test') ? 'https://wildfire.paloaltonetworks.com/publicapi/test/pe' : 'https://' + server + '/publicapi/get/verdicts/changed';

            request({
                method: 'POST',
                uri: uri,
                json: true,
                body: body
            }, function (error, response, body) {
                if (error || (!response.statusCode == 200)) {
                    return callback(error || new Error('Request Error'));
                }
                console.log('wildfire payload:', body);
                callback(null, body);
            });

        }
    }

    RED.nodes.registerType("wildfire service", Service);
};
